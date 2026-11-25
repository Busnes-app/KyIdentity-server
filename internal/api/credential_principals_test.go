package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// credentialPrincipalCallers are the only functions that may ask CredentialPrincipal (the
// tenancy design's credential_principals), each with its reason. They decide whether a
// credential may be tried, never whether access is granted.
var credentialPrincipalCallers = map[string]string{
	"api.loginRefusal":    "user lookup, password and lockout of interactive sign-in",
	"api.resolveMFAToken": "the second-factor step of interactive sign-in",
}

// A new caller fails here until it is listed with a reason.
func TestCredentialPrincipalCallers(t *testing.T) {
	found := map[string]bool{}
	for _, dir := range []string{".", "../oauth", "../mfa", "../auth", "../sync", "../../cmd/kyidentity"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range file.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "CredentialPrincipal" {
						found[file.Name.Name+"."+fn.Name.Name] = true
					}
					return true
				})
			}
		}
	}
	var got []string
	for name := range found {
		got = append(got, name)
		if credentialPrincipalCallers[name] == "" {
			t.Errorf("%s asks CredentialPrincipal: list it in credentialPrincipalCallers with its reason, or read the org", name)
		}
	}
	for name := range credentialPrincipalCallers {
		if !found[name] {
			t.Errorf("credentialPrincipalCallers lists %s, which no longer asks it", name)
		}
	}
	slices.Sort(got)
	t.Logf("callers: %v", got)
}
