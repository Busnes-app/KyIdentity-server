package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// auditDiscardAllowed names call sites ("file:function") that may drop an audit write's
// error, each with its reason. Mutations commit their row with Prepare; observations use
// Observe, which logs the loss. Neither needs an entry here.
var auditDiscardAllowed = map[string]string{}

// TestAuditWritesAreNeverDiscarded fails when an audit Record (or a handler's record
// wrapper) runs as a bare statement or into blank identifiers: a security change reported as
// done while its audit row silently vanished leaves no trail, only the look of one.
func TestAuditWritesAreNeverDiscarded(t *testing.T) {
	for _, dir := range []string{".", "../../cmd/kyidentity"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, site := range discardedAuditWrites(t, path) {
				if _, ok := auditDiscardAllowed[site.key]; !ok {
					t.Errorf("%s discards an audit write's error; use Prepare with the mutation, or Observe", site.pos)
				}
			}
		}
	}
}

type auditSite struct{ key, pos string }

func discardedAuditWrites(t *testing.T, path string) []auditSite {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sites []auditSite
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		flag := func(e ast.Expr) {
			call, ok := e.(*ast.CallExpr)
			if !ok {
				return
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Record" || sel.Sel.Name == "record") {
				sites = append(sites, auditSite{filepath.Base(path) + ":" + fn.Name.Name, fset.Position(call.Pos()).String()})
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.ExprStmt:
				flag(s.X)
			case *ast.GoStmt:
				flag(s.Call)
			case *ast.DeferStmt:
				flag(s.Call)
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					if id, ok := lhs.(*ast.Ident); !ok || id.Name != "_" {
						return true
					}
				}
				for _, rhs := range s.Rhs {
					flag(rhs)
				}
			}
			return true
		})
	}
	return sites
}
