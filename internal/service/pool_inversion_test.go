package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Asking the pool for a connection while already holding one.
//
// This is the shape that deadlocked writes on a 26.9M-contact dataset:
//
//	registerTx(tx)          <- holds a transaction, i.e. a pool connection
//	  mergeIntoBlob(tx)
//	    KeyRing.Newest      <- Pool.QueryRow: asks for a SECOND connection
//
// Once concurrency reaches the pool size, every connection is held by a
// goroutine in that position and none can be released. It resolves only when
// clients time out. Writes measured 516 rps at c=8 and 18 rps with 150
// timeouts at c=32, with the database at zero active queries throughout.
//
// The defect is invisible to reading (each function is individually
// reasonable), to line coverage (every line runs), and to the race detector
// (there is no race). What finds it is this: the call graph, walked from
// every function that takes a pgx.Tx.
//
// The guard is name-based rather than type-resolved, which makes it
// approximate in one direction only: it can miss a call through an interface
// or a function value. It does not produce false positives, because a hit
// means some function reachable from a tx-holder literally names `.Pool.` -
// and every such hit is either a bug or a decision worth writing down.

type fnInfo struct {
	name     string
	where    string
	takesTx  bool
	usesPool bool
	calls    []string
}

func parseFuncs(t *testing.T, dirs ...string) map[string]*fnInfo {
	t.Helper()
	root := repoRootForInversion(t)
	fset := token.NewFileSet()
	out := map[string]*fnInfo{}
	for _, dir := range dirs {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				fi := &fnInfo{
					name:  fd.Name.Name,
					where: rel + ":" + itoa(fset.Position(fd.Pos()).Line),
				}
				if fd.Type.Params != nil {
					for _, p := range fd.Type.Params.List {
						if exprText(p.Type) == "pgx.Tx" {
							fi.takesTx = true
						}
					}
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						recv := exprText(sel.X)
						// `x.Pool.Query(...)`, `k.Pool.Exec(...)`, and the
						// bare `pool.Acquire(...)` form.
						if strings.HasSuffix(recv, ".Pool") || recv == "Pool" || recv == "pool" {
							switch sel.Sel.Name {
							case "Query", "QueryRow", "Exec", "Begin", "BeginTx", "Acquire", "SendBatch", "CopyFrom":
								fi.usesPool = true
							}
						}
						fi.calls = append(fi.calls, sel.Sel.Name)
					}
					if id, ok := call.Fun.(*ast.Ident); ok {
						fi.calls = append(fi.calls, id.Name)
					}
					return true
				})
				// Distinct names only; a collision would merge two functions
				// and is reported rather than silently resolved.
				if prev, dup := out[fi.name]; dup {
					fi.calls = append(fi.calls, prev.calls...)
					fi.takesTx = fi.takesTx || prev.takesTx
					fi.usesPool = fi.usesPool || prev.usesPool
					fi.where = prev.where + ", " + fi.where
				}
				out[fi.name] = fi
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestNoPoolAcquireWhileHoldingATransaction walks the call graph from every
// function that takes a pgx.Tx and fails on any that can reach a pool
// acquisition.
func TestNoPoolAcquireWhileHoldingATransaction(t *testing.T) {
	funcs := parseFuncs(t, "internal/service", "internal/audit", "internal/auth")
	if len(funcs) < 50 {
		t.Fatalf("parsed only %d functions - the walk has stopped seeing the tree and "+
			"every conclusion below is vacuous", len(funcs))
	}

	// Decisions, each with the reason it is not the deadlock shape. An entry
	// here is a claim someone has to defend in review.
	allowed := map[string]string{
		// The CLI helper opens the transaction it passes; it holds none of
		// its own beforehand.
		"auditOperator": "opens the transaction it passes; holds none of its own beforehand",

		// epochCheckDue is the ONE remaining edge, and it is the one that
		// caused the outage - so the reason has to be exact.
		//
		// It queries only for a ring with NO background refresher. `serve` -
		// the sole long-lived, concurrent process - starts one at boot
		// (TestServeStartsTheKeyRingRefresher pins that), and a
		// refresher-owned ring never reaches this code
		// (TestKeyRingReadPathTouchesNoDatabase pins that).
		//
		// Every other ring belongs to a single-threaded CLI command:
		// `keys rotate|retire|list|rekey`, `bootstrap`, `import`. One
		// goroutine cannot exhaust a pool by waiting on itself, and those
		// commands NEED the inline check - it is what makes a replica notice
		// another process's rotation within a second instead of a TTL
		// (CONCURRENCY-CORE-4, TestRetireDoesNotOrphanAnotherReplicasTokens).
		//
		// If a CLI command ever becomes concurrent - parallelising the rekey
		// sweep is planned - it must start a refresher first, or this
		// exemption stops being true.
		"epochCheckDue": "queries only when no background refresher owns the ring; `serve` always starts one, and every other ring is single-threaded CLI",

		// The cold-load fallback, exempt for the same reason and pinned the
		// same way. errIfRefresherOwned returns BEFORE this call whenever a
		// refresher owns the ring, so `serve` cannot reach it - the ring is
		// loaded synchronously inside StartRefresher, and a miss afterwards
		// is an error rather than a query
		// (TestRefresherOwnedRingRefusesToQueryFromTheRequestPath).
		"refresh": "unreachable on a refresher-owned ring; errIfRefresherOwned turns a cache miss into an error instead of a query",
	}

	var findings []string
	for name, fi := range funcs {
		if !fi.takesTx {
			continue
		}
		if _, ok := allowed[name]; ok {
			continue
		}
		if path, hit := reachesPool(funcs, name, map[string]bool{}, allowed); hit {
			findings = append(findings,
				fi.where+"  "+strings.Join(path, " -> ")+"  acquires a pool connection")
		}
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("functions that hold a transaction and then ask the pool for another "+
			"connection:\n  %s\n\n"+
			"Under concurrency at or above the pool size this deadlocks: every connection is\n"+
			"held by a goroutine in this position, so the one it waits for is never freed.\n"+
			"Resolve what you need BEFORE opening the transaction, pass the tx down, or - if\n"+
			"this call genuinely cannot be in that position - add it to `allowed` with the\n"+
			"reason.", strings.Join(findings, "\n  "))
	}
}

// reachesPool walks callees depth-first and returns the path to the first
// pool acquisition it finds.
func reachesPool(funcs map[string]*fnInfo, name string, seen map[string]bool, allowed map[string]string) ([]string, bool) {
	if seen[name] {
		return nil, false
	}
	// An allowed function stops the walk wherever it appears, not only when
	// it is the starting point: the exemption is about that CALL, and every
	// path through it inherits the reason recorded against it.
	if _, ok := allowed[name]; ok {
		return nil, false
	}
	seen[name] = true
	fi, ok := funcs[name]
	if !ok {
		return nil, false
	}
	if fi.usesPool {
		return []string{name}, true
	}
	for _, callee := range fi.calls {
		if callee == name {
			continue
		}
		if path, hit := reachesPool(funcs, callee, seen, allowed); hit {
			return append([]string{name}, path...), true
		}
	}
	return nil, false
}

func repoRootForInversion(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the working directory")
	return ""
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprText(v.X)
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
