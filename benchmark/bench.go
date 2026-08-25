// Command bench is a head-to-head benchmark harness for Sunder and
// Databunker running on the same machine (see benchmark/README.md for the
// methodology and fairness notes).
//
// Operations:
//
//	write create one contact/user per request (email, phone, name + 2 custom fields)
//	read fetch by CID (Sunder: one attribute, purpose-checked+audited) /
//	 by token (Databunker: full record)
//	lookup find by email (Sunder: POST /v1/lookup; Databunker: GET /v1/user/email/...)
//
// Usage:
//
//	bench -target sunder -base http://localhost:8080 -cred '<id.secret>' -op write -n 5000 -c 16
//	bench -target databunker -base http://localhost:3000 -cred DEMO -op write -n 5000 -c 16
//
// read/lookup phases reuse identities created by a preceding write run with
// the same -seed, so run write first.
package main

import (
	"bytes"
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

type result struct {
	lat time.Duration
	err bool
}

func main() {
	target := flag.String("target", "", "sunder | databunker")
	base := flag.String("base", "", "base URL")
	cred := flag.String("cred", "", "Sunder bearer credential or Databunker root token")
	op := flag.String("op", "write", "write | read | lookup")
	n := flag.Int("n", 5000, "total requests")
	c := flag.Int("c", 16, "concurrent workers")
	seed := flag.String("seed", "bench", "identity namespace (ties read/lookup to a write run)")
	purpose := flag.String("purpose", "benchmark", "Sunder purpose for attribute reads")
	keyspace := flag.Int("keyspace", 0, "if >0, spread the N requests over a loaded set this large instead of hitting indices 0..N-1")
	flag.Parse()
	if *target == "" || *base == "" || *cred == "" {
		fmt.Fprintln(os.Stderr, "need -target, -base, -cred")
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns: *c * 2, MaxIdleConnsPerHost: *c * 2,
		},
	}

	// For read ops we need per-index handles (Sunder CID / Databunker token):
	// resolve them up front via email lookup so handle resolution is not
	// part of the measured read path.
	var handles []string
	if *op == "read" {
		handles = make([]string, *n)
		var wg sync.WaitGroup
		sem := make(chan struct{}, *c)
		for i := 0; i < *n; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer func() { wg.Done(); <-sem }()
				h, err := resolveHandle(client, *target, *base, *cred, email(*seed, scatter(i, *keyspace)))
				if err != nil {
					fmt.Fprintf(os.Stderr, "resolve %d: %v\n", i, err)
					os.Exit(1)
				}
				handles[i] = h
			}(i)
		}
		wg.Wait()
	}

	results := make([]result, *n)
	var idx int64 = -1
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < *c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&idx, 1))
				if i >= *n {
					return
				}
				t0 := time.Now()
				err := doOne(client, *target, *base, *cred, *op, *seed, *purpose, i, *keyspace, handles)
				results[i] = result{lat: time.Since(t0), err: err != nil}
				if err != nil && i < 5 {
					fmt.Fprintf(os.Stderr, "req %d: %v\n", i, err)
				}
			}
		}()
	}
	wg.Wait()
	wall := time.Since(start)

	lats := make([]time.Duration, 0, *n)
	errs := 0
	for _, r := range results {
		if r.err {
			errs++
			continue
		}
		lats = append(lats, r.lat)
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p float64) time.Duration {
		if len(lats) == 0 {
			return 0
		}
		i := int(p * float64(len(lats)-1))
		return lats[i]
	}
	out := map[string]any{
		"target": *target, "op": *op, "n": *n, "concurrency": *c,
		"errors":  errs,
		"wall_s":  fmt.Sprintf("%.2f", wall.Seconds()),
		"rps":     fmt.Sprintf("%.1f", float64(len(lats))/wall.Seconds()),
		"p50_ms":  fmt.Sprintf("%.2f", pct(0.50).Seconds()*1000),
		"p95_ms":  fmt.Sprintf("%.2f", pct(0.95).Seconds()*1000),
		"p99_ms":  fmt.Sprintf("%.2f", pct(0.99).Seconds()*1000),
		"mean_ms": fmt.Sprintf("%.2f", mean(lats).Seconds()*1000),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	if errs > *n/100 {
		os.Exit(1)
	}
}

func mean(l []time.Duration) time.Duration {
	if len(l) == 0 {
		return 0
	}
	var sum time.Duration
	for _, v := range l {
		sum += v
	}
	return sum / time.Duration(len(l))
}

func email(seed string, i int) string { return fmt.Sprintf("%s-%d@bench.example", seed, i) }

// scatter maps a sequential request counter onto a large loaded keyspace.
// Without it a lookup run walks indices 0..n-1, which on a set far larger
// than RAM measures the buffer cache rather than the index: those few pages
// stay resident for the whole run. Multiplying by an odd constant coprime
// with any power of two and taking it mod the keyspace spreads the probes
// uniformly while staying deterministic, so two runs are comparable.
func scatter(i, keyspace int) int {
	if keyspace <= 0 {
		return i
	}
	const knuth = 2654435761 // Knuth's multiplicative hash constant, odd
	return int((uint64(i) * knuth) % uint64(keyspace))
}

// phone is namespaced by the seed (FNV offset) so consecutive benchmark runs
// never collide on the unique phone index of either system.
func phone(seed string, i int) string {
	h := uint64(14695981039346656037)
	for _, b := range []byte(seed) {
		h = (h ^ uint64(b)) * 1099511628211
	}
	return fmt.Sprintf("+385%09d", (h%900+100)*1000000+uint64(i)%1000000)
}

func doOne(client *http.Client, target, base, cred, op, seed, purpose string, i, keyspace int, handles []string) error {
	switch target + "/" + op {
	case "sunder/write":
		return call(client, "POST", base+"/v1/contacts", sunderAuth(cred), map[string]any{
			"email": email(seed, i), "phone": phone(seed, i), "name": fmt.Sprintf("Bench User%d", i),
			"attributes": map[string]string{"loyalty_tier": "gold", "segment": "smb"},
		}, 201)
	case "databunker/write":
		return call(client, "POST", base+"/v1/user", bunkerAuth(cred), map[string]any{
			"email": email(seed, i), "phone": phone(seed, i), "name": fmt.Sprintf("Bench User%d", i),
			"loyalty_tier": "gold", "segment": "smb", "login": fmt.Sprintf("%s-%d", seed, i),
		}, 200)
	case "sunder/read":
		return call(client, "GET",
			base+"/v1/contacts/"+handles[i]+"/attributes/email?purpose="+purpose,
			sunderAuth(cred), nil, 200)
	case "databunker/read":
		return call(client, "GET", base+"/v1/user/token/"+handles[i], bunkerAuth(cred), nil, 200)
	case "sunder/lookup":
		return call(client, "POST", base+"/v1/lookup", sunderAuth(cred),
			map[string]any{"email": email(seed, scatter(i, keyspace))}, 200)
	case "databunker/lookup":
		return call(client, "GET", base+"/v1/user/email/"+email(seed, scatter(i, keyspace)),
			bunkerAuth(cred), nil, 200)
	default:
		return fmt.Errorf("unknown target/op %s/%s", target, op)
	}
}

func resolveHandle(client *http.Client, target, base, cred, mail string) (string, error) {
	var out struct {
		CID   string `json:"cid"`
		Token string `json:"token"`
	}
	switch target {
	case "sunder":
		if err := callInto(client, "POST", base+"/v1/lookup", sunderAuth(cred),
			map[string]any{"email": mail}, 200, &out); err != nil {
			return "", err
		}
		return out.CID, nil
	default:
		if err := callInto(client, "GET", base+"/v1/user/email/"+mail, bunkerAuth(cred), nil, 200, &out); err != nil {
			return "", err
		}
		return out.Token, nil
	}
}

func sunderAuth(cred string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + cred}
}
func bunkerAuth(cred string) map[string]string {
	return map[string]string{"X-Bunker-Token": cred}
}

func call(client *http.Client, method, url string, headers map[string]string, body any, want int) error {
	return callInto(client, method, url, headers, body, want, nil)
}

func callInto(client *http.Client, method, url string, headers map[string]string, body any, want int, into any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s: status %d body %.120s", method, url, resp.StatusCode, raw)
	}
	if into != nil {
		return json.Unmarshal(raw, into)
	}
	return nil
}
