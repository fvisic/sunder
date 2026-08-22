// Command migrate-databunker moves user records from a Databunker instance
// into Sunder.
//
// It pages through Databunker's admin list API (POST /v1/users - requires
// `list_users: true` under `generic:` in databunker.yaml), registers each
// record as a Sunder contact (identifiers become searchable HMAC tokens,
// everything else lands in the caller-scope encrypted attribute blob), and
// writes a CSV mapping <databunker token> -> <sunder CID> so client systems
// can re-key their references.
//
// Usage:
//
//	go run ./migrate/databunker \
//	  -source http://localhost:3000 -source-token <root token> \
//	  -target http://localhost:8080 -cred '<client_id.secret>' \
//	  -map-out mapping.csv [-batch 100] [-c 8] [-dry-run]
//
// The Sunder client needs the contacts.register action. Records without an
// email or phone cannot be registered (nothing searchable) and are reported
// as skipped. Databunker agreements/consents are not migrated automatically:
// map them to Sunder consent purposes per your own legal analysis.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type bunkerRow struct {
	Token   string          `json:"token"`
	Private json.RawMessage `json:"private"`
}

// profile decodes the record payload: Databunker returns it either as a
// JSON object or (list API) as a base64-encoded JSON string.
func (r bunkerRow) profile() (map[string]any, error) {
	var direct map[string]any
	if err := json.Unmarshal(r.Private, &direct); err == nil {
		return direct, nil
	}
	var b64 string
	if err := json.Unmarshal(r.Private, &b64); err != nil {
		return nil, fmt.Errorf("unrecognized private payload shape")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("private payload base64: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("private payload json: %w", err)
	}
	return out, nil
}

type listResponse struct {
	Status string      `json:"status"`
	Total  int64       `json:"total"`
	Rows   []bunkerRow `json:"rows"`
}

type migrated struct {
	token, cid string
}

func main() {
	source := flag.String("source", "", "Databunker base URL")
	sourceToken := flag.String("source-token", "", "Databunker root/admin token")
	target := flag.String("target", "", "Sunder base URL")
	cred := flag.String("cred", "", "Sunder client credential (contacts.register)")
	mapOut := flag.String("map-out", "", "CSV output: databunker_token,sunder_cid (recommended)")
	batch := flag.Int("batch", 100, "Databunker page size")
	conc := flag.Int("c", 8, "concurrent Sunder registrations")
	dryRun := flag.Bool("dry-run", false, "read and validate only; register nothing")
	keepToken := flag.Bool("keep-source-token", true, "store the Databunker token as attribute databunker_token")
	flag.Parse()
	if *source == "" || *sourceToken == "" || *target == "" || (*cred == "" && !*dryRun) {
		fmt.Fprintln(os.Stderr, "need -source, -source-token, -target and -cred (or -dry-run)")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var okCount, skipCount, failCount atomic.Int64
	var mu sync.Mutex
	var mappings []migrated

	work := make(chan bunkerRow, *conc*2)
	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for row := range work {
				cid, err := register(client, *target, *cred, row, *keepToken, *dryRun)
				switch {
				case err == errNoIdentifier:
					skipCount.Add(1)
					fmt.Fprintf(os.Stderr, "skip %s: no email or phone\n", row.Token)
				case err != nil:
					failCount.Add(1)
					fmt.Fprintf(os.Stderr, "fail %s: %v\n", row.Token, err)
				default:
					okCount.Add(1)
					mu.Lock()
					mappings = append(mappings, migrated{row.Token, cid})
					mu.Unlock()
				}
			}
		}()
	}

	var offset, total int64
	for {
		page, err := listPage(client, *source, *sourceToken, offset, *batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list users (offset %d): %v\n", offset, err)
			os.Exit(1)
		}
		total = page.Total
		for _, row := range page.Rows {
			work <- row
		}
		offset += int64(len(page.Rows))
		if len(page.Rows) == 0 || offset >= page.Total {
			break
		}
	}
	close(work)
	wg.Wait()

	if *mapOut != "" && len(mappings) > 0 {
		sort.Slice(mappings, func(i, j int) bool { return mappings[i].token < mappings[j].token })
		f, err := os.Create(*mapOut)
		if err != nil {
			fmt.Fprintln(os.Stderr, "map-out:", err)
			os.Exit(1)
		}
		w := csv.NewWriter(f)
		_ = w.Write([]string{"databunker_token", "sunder_cid"})
		for _, m := range mappings {
			_ = w.Write([]string{m.token, m.cid})
		}
		w.Flush()
		_ = f.Close()
	}

	mode := ""
	if *dryRun {
		mode = " (dry run)"
	}
	fmt.Printf("migration complete%s: %d migrated, %d skipped, %d failed (source total %d)\n",
		mode, okCount.Load(), skipCount.Load(), failCount.Load(), total)
	if *mapOut != "" {
		fmt.Printf("token->CID mapping written to %s - use it to re-key client systems\n", *mapOut)
	}
	if failCount.Load() > 0 {
		os.Exit(1)
	}
}

func listPage(client *http.Client, base, token string, offset int64, limit int) (*listResponse, error) {
	url := fmt.Sprintf("%s/v1/users?offset=%d&limit=%d", base, offset, limit)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Bunker-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("status 403 - enable `list_users: true` under `generic:` in databunker.yaml and use the root token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %.200s", resp.StatusCode, raw)
	}
	var out listResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

var errNoIdentifier = fmt.Errorf("no searchable identifier")

// register maps one Databunker record onto Sunder's register-contact call.
// Known identifier keys feed search tokens; every other scalar in the
// profile becomes a custom attribute (values stringified).
func register(client *http.Client, base, cred string, row bunkerRow, keepToken, dryRun bool) (string, error) {
	body := map[string]any{}
	attrs := map[string]string{}

	str := func(v any) string {
		switch t := v.(type) {
		case string:
			return t
		case float64:
			return fmt.Sprintf("%g", t)
		case bool:
			return fmt.Sprintf("%t", t)
		default:
			b, _ := json.Marshal(t)
			return string(b)
		}
	}

	profile, err := row.profile()
	if err != nil {
		return "", err
	}
	var name, first, last string
	for k, v := range profile {
		switch k {
		case "email":
			body["email"] = str(v)
		case "phone":
			body["phone"] = str(v)
		case "name":
			name = str(v)
		case "first":
			first = str(v)
		case "last":
			last = str(v)
		default:
			// Reserved names are generated by Sunder itself; prefix clashes.
			key := k
			if k == "email" || k == "phone" {
				key = "src_" + k
			}
			attrs[key] = str(v)
		}
	}
	if name == "" && (first != "" || last != "") {
		name = first
		if last != "" {
			if name != "" {
				name += " "
			}
			name += last
		}
	}
	if name != "" {
		body["name"] = name
	}
	if keepToken {
		attrs["databunker_token"] = row.Token
	}
	if len(attrs) > 0 {
		body["attributes"] = attrs
	}
	if body["email"] == nil && body["phone"] == nil {
		return "", errNoIdentifier
	}
	if dryRun {
		return "", nil
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", base+"/v1/contacts", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("sunder status %d: %.200s", resp.StatusCode, raw)
	}
	var out struct {
		CID string `json:"cid"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.CID == "" {
		return "", fmt.Errorf("bad register response: %.120s", raw)
	}
	return out.CID, nil
}
