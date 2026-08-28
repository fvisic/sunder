package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Discovering every audit action the code can write.
//
// The first version of this scanner was a regexp for `Action: "..."`. It
// passed green while four actions - `client.create`, `webhook.set`,
// `retention.set` and `dsr.erase.delivered` - were being written and were in
// no registry, because each reaches the Entry through a HELPER that takes the
// action as an ordinary string parameter:
//
//	auditOperator(ctx, pool, "client.create", ...)   // cmd/sunder/main.go
//	terminal(e, "DELIVERED", "dsr.erase.delivered")  // internal/service/gdpr.go
//
// Three of those four are privileged operator acts - exactly what the
// registry claims to cover. A regexp over syntax cannot see them, so this
// scanner works on the AST instead and follows one level of forwarding.
//
// The property that makes it a CLOSED set rather than a better guess: an
// `Action:` value in a shape the scanner does not understand is a FAILURE,
// not a skip. A new way of producing an action cannot slip through quietly;
// it has to be taught here first.

// actionSource is one way the tree produces an audit action.
type actionSource struct {
	Action string // the action string, or a family prefix
	Where  string // file:line of the call site that produces it
	Family bool   // true when this is a prefix concatenated with a suffix
}

// forwarder is a function that takes an action as a parameter and puts it
// into an Entry - the shape the regexp scanner was blind to.
type forwarder struct {
	name     string // function name, or the variable a func literal is bound to
	argIndex int    // which parameter carries the action
}

type scanner struct {
	t          *testing.T
	fset       *token.FileSet
	files      map[string]*ast.File // rel path -> parsed file
	consts     map[string]string    // Ident or pkg.Ident -> string value
	forwarders map[string]forwarder
	sources    []actionSource
	unknown    []string
}

func newScanner(t *testing.T) *scanner {
	t.Helper()
	s := &scanner{
		t: t, fset: token.NewFileSet(),
		files:      map[string]*ast.File{},
		consts:     map[string]string{},
		forwarders: map[string]forwarder{},
	}
	root := repoRoot(t)
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(s.fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			s.files[filepath.ToSlash(rel)] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(s.files) == 0 {
		t.Fatal("parsed no source files - the scanner would report an empty vocabulary")
	}
	s.collectConsts()
	s.collectForwarders()
	s.collectSources()
	return s
}

// collectConsts records every package-level string constant, under both its
// bare name and its `audit.`-qualified name, so `Action: audit.ActionLookup`
// resolves to "lookup".
func (s *scanner) collectConsts() {
	for rel, f := range s.files {
		pkg := "audit"
		if !strings.Contains(rel, "/audit/") {
			pkg = f.Name.Name
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, err := strconv.Unquote(lit.Value)
						if err != nil {
							continue
						}
						s.consts[name.Name] = v
						s.consts[pkg+"."+name.Name] = v
					}
				}
			}
		}
	}
}

// enclosingFunc returns the name of the function containing pos, and its
// parameter names in order. A func literal bound to a variable is named by
// that variable, which is how `terminal := func(...)` becomes callable.
func enclosingFunc(f *ast.File, target ast.Node) (string, []string) {
	var name string
	var params []string
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if n.Pos() > target.Pos() || n.End() < target.End() {
			return true
		}
		switch fn := n.(type) {
		case *ast.FuncDecl:
			name, params = fn.Name.Name, paramNames(fn.Type)
		case *ast.AssignStmt:
			if len(fn.Lhs) == 1 && len(fn.Rhs) == 1 {
				if id, ok := fn.Lhs[0].(*ast.Ident); ok {
					if lit, ok := fn.Rhs[0].(*ast.FuncLit); ok {
						name, params = id.Name, paramNames(lit.Type)
					}
				}
			}
		}
		return true
	})
	return name, params
}

func paramNames(ft *ast.FuncType) []string {
	var out []string
	if ft.Params == nil {
		return out
	}
	for _, field := range ft.Params.List {
		if len(field.Names) == 0 {
			out = append(out, "_")
			continue
		}
		for _, n := range field.Names {
			out = append(out, n.Name)
		}
	}
	return out
}

// entryActionValues yields the expression assigned to the Action field of
// every audit Entry composite literal in the tree.
func (s *scanner) eachEntryAction(fn func(rel string, f *ast.File, value ast.Expr, pos token.Pos)) {
	for rel, f := range s.files {
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if !isEntryType(cl.Type) {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Action" {
					fn(rel, f, kv.Value, kv.Pos())
				}
			}
			return true
		})
	}
}

func isEntryType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "Entry"
	case *ast.SelectorExpr:
		return t.Sel.Name == "Entry"
	}
	return false
}

// collectForwarders finds functions whose Action field is one of their own
// parameters. Those are the helpers a syntax scan cannot see through.
func (s *scanner) collectForwarders() {
	s.eachEntryAction(func(rel string, f *ast.File, value ast.Expr, pos token.Pos) {
		id, ok := value.(*ast.Ident)
		if !ok {
			return
		}
		if _, isConst := s.consts[id.Name]; isConst {
			return
		}
		name, params := enclosingFunc(f, value)
		if name == "" {
			return
		}
		for i, p := range params {
			if p == id.Name {
				s.forwarders[name] = forwarder{name: name, argIndex: i}
				return
			}
		}
	})
}

// collectSources resolves every Action expression, and every call to a
// forwarder, into the action strings they can produce.
func (s *scanner) collectSources() {
	s.eachEntryAction(func(rel string, f *ast.File, value ast.Expr, pos token.Pos) {
		where := rel + ":" + strconv.Itoa(s.fset.Position(pos).Line)
		switch v := value.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				if str, err := strconv.Unquote(v.Value); err == nil {
					s.sources = append(s.sources, actionSource{Action: str, Where: where})
					return
				}
			}
		case *ast.BinaryExpr:
			// `"portal.mail." + strings.ToLower(status)` - a family.
			if lit, ok := v.X.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if str, err := strconv.Unquote(lit.Value); err == nil {
					s.sources = append(s.sources, actionSource{Action: str, Where: where, Family: true})
					return
				}
			}
		case *ast.Ident:
			if str, ok := s.consts[v.Name]; ok {
				s.sources = append(s.sources, actionSource{Action: str, Where: where})
				return
			}
			// A parameter: this is a forwarder, resolved at its call sites.
			if name, params := enclosingFunc(f, value); name != "" {
				for _, p := range params {
					if p == v.Name {
						return
					}
				}
			}
			// A local scanned OUT OF THE DATABASE. Verify and Drain rebuild
			// an Entry from a row that already exists in order to recompute
			// its hash - they read the vocabulary, they do not add to it, so
			// the action there is data and not a call site. The condition is
			// checked mechanically rather than promised in a comment: the
			// value must actually arrive through rows.Scan(&ident).
			if scannedFromDB(f, value, v.Name) {
				return
			}
		case *ast.SelectorExpr:
			if str, ok := s.consts[exprString(v)]; ok {
				s.sources = append(s.sources, actionSource{Action: str, Where: where})
				return
			}
		case *ast.CallExpr:
			// `c.lookupAction(...)` - take the string constants it returns.
			if got := s.returnedConstants(v); len(got) > 0 {
				for _, str := range got {
					s.sources = append(s.sources, actionSource{Action: str, Where: where})
				}
				return
			}
		}
		s.unknown = append(s.unknown, where+": "+exprString(value))
	})

	// Now the forwarders' call sites.
	for _, f := range s.files {
		rel := ""
		for k, v := range s.files {
			if v == f {
				rel = k
				break
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := calleeName(call.Fun)
			fw, ok := s.forwarders[name]
			if !ok || fw.argIndex >= len(call.Args) {
				return true
			}
			where := rel + ":" + strconv.Itoa(s.fset.Position(call.Pos()).Line)
			arg := call.Args[fw.argIndex]
			switch v := arg.(type) {
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					if str, err := strconv.Unquote(v.Value); err == nil {
						s.sources = append(s.sources, actionSource{Action: str, Where: where})
						return true
					}
				}
			case *ast.Ident:
				if str, ok := s.consts[v.Name]; ok {
					s.sources = append(s.sources, actionSource{Action: str, Where: where})
					return true
				}
			case *ast.SelectorExpr:
				if str, ok := s.consts[exprString(v)]; ok {
					s.sources = append(s.sources, actionSource{Action: str, Where: where})
					return true
				}
			}
			s.unknown = append(s.unknown,
				where+": argument "+strconv.Itoa(fw.argIndex)+" of "+name+" is "+exprString(arg))
			return true
		})
	}
}

// returnedConstants collects the string constants a locally-defined function
// can return, so `Action: c.lookupAction(...)` resolves to its three values.
func (s *scanner) returnedConstants(call *ast.CallExpr) []string {
	name := calleeName(call.Fun)
	if name == "" {
		return nil
	}
	var out []string
	for _, f := range s.files {
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name || fn.Body == nil {
				return true
			}
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				ret, ok := m.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, r := range ret.Results {
					switch v := r.(type) {
					case *ast.BasicLit:
						if v.Kind == token.STRING {
							if str, err := strconv.Unquote(v.Value); err == nil {
								out = append(out, str)
							}
						}
					case *ast.Ident:
						if str, ok := s.consts[v.Name]; ok {
							out = append(out, str)
						}
					case *ast.SelectorExpr:
						if str, ok := s.consts[exprString(v)]; ok {
							out = append(out, str)
						}
					}
				}
				return true
			})
			return true
		})
	}
	return out
}

func calleeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.BasicLit:
		return v.Value
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "(...)"
	case *ast.BinaryExpr:
		return exprString(v.X) + " + " + exprString(v.Y)
	}
	return "<expression>"
}

// TestScannerUnderstandsEveryActionExpression is the property that makes the
// set closed rather than merely large: a way of producing an action that this
// scanner does not recognise fails the build. Without it, the next helper
// added would repeat exactly the miss that let four actions go unregistered.
func TestScannerUnderstandsEveryActionExpression(t *testing.T) {
	s := newScanner(t)
	if len(s.unknown) > 0 {
		sort.Strings(s.unknown)
		t.Fatalf("audit Entry.Action values the scanner cannot resolve:\n  %s\n\n"+
			"Teach internal/audit/scan_test.go about this shape before merging. An\n"+
			"unresolvable action is one the closed-set guard silently stops covering.",
			strings.Join(s.unknown, "\n  "))
	}
	if len(s.sources) < 40 {
		t.Fatalf("the scanner found only %d action sources - it has stopped seeing most "+
			"of the tree, and every guard built on it is now vacuous", len(s.sources))
	}
}

// TestScannerSeesThroughForwardingHelpers pins the specific blind spot,
// by name. If someone rewrites the scanner and loses this capability, the
// four actions it was blind to come back.
func TestScannerSeesThroughForwardingHelpers(t *testing.T) {
	s := newScanner(t)
	if len(s.forwarders) == 0 {
		t.Fatal("no forwarding helpers discovered - auditOperator and terminal both take " +
			"the action as a parameter, so finding none means the discovery broke")
	}
	got := map[string]bool{}
	for _, src := range s.sources {
		got[src.Action] = true
	}
	// These four reach the trail ONLY through a helper.
	for _, want := range []string{
		"client.create", "webhook.set", "retention.set", "dsr.erase.delivered",
	} {
		if !got[want] {
			t.Errorf("%q is written through a forwarding helper and the scanner missed it", want)
		}
	}
}

// TestEveryProducibleActionIsRegistered is the closed-enum guard proper, now
// over everything the AST scan can reach rather than everything a regexp
// could match.
func TestEveryProducibleActionIsRegistered(t *testing.T) {
	s := newScanner(t)
	byAction := map[string][]string{}
	for _, src := range s.sources {
		if src.Family {
			if !familyExists(src.Action) {
				t.Errorf("%s concatenates onto the prefix %q, which is not a registered "+
					"family in actions.go", src.Where, src.Action)
			}
			continue
		}
		byAction[src.Action] = append(byAction[src.Action], src.Where)
	}
	var missing []string
	for action, wheres := range byAction {
		if !IsKnownAction(action) {
			sort.Strings(wheres)
			missing = append(missing, action+"  (written at "+strings.Join(wheres, ", ")+")")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("audit actions the code can write but actions.go does not register:\n  %s\n\n"+
			"Add each with a one-line meaning. Until then, docs/API.md and\n"+
			"docs-site/docs/admin/audit-chain.md promise a closed set that is not closed.",
			strings.Join(missing, "\n  "))
	}
}

// TestNoRegisteredActionIsUnreachable replaces the old stale check. It needs
// no exemption list at all now: the AST scan sees the forwarded actions, so
// anything registered and unreachable really is dead.
func TestNoRegisteredActionIsUnreachable(t *testing.T) {
	s := newScanner(t)
	reachable := map[string]bool{}
	for _, src := range s.sources {
		reachable[src.Action] = true
	}
	var dead []string
	for action := range Actions {
		if !reachable[action] {
			dead = append(dead, action)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Fatalf("registered audit actions no production call site can produce:\n  %s\n\n"+
			"Remove the entry, or - if the scanner genuinely cannot see the call site - \n"+
			"teach it that shape rather than adding an unchecked exemption.",
			strings.Join(dead, "\n  "))
	}
}

func familyExists(prefix string) bool {
	for _, f := range Families {
		if f.Prefix == prefix {
			return true
		}
	}
	return false
}

// scannedFromDB reports whether ident is filled by a rows.Scan in the same
// function as target - i.e. the action came from a database row rather than
// from this code. Anything else that looks like a local variable stays
// unresolved and fails the guard, which is the point.
func scannedFromDB(f *ast.File, target ast.Node, ident string) bool {
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		if fn.Pos() > target.Pos() || fn.End() < target.End() {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok || calleeName(call.Fun) != "Scan" {
				return true
			}
			for _, arg := range call.Args {
				un, ok := arg.(*ast.UnaryExpr)
				if !ok || un.Op != token.AND {
					continue
				}
				if id, ok := un.X.(*ast.Ident); ok && id.Name == ident {
					found = true
				}
			}
			return true
		})
		return true
	})
	return found
}
