package keycmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The commands the owner's tools print go through one function of their
// name (ownerkey.Command, ownerkey.VerifyOwnerCommand, the prog of
// verifycmd and apicmd), so that under trajrl they are trajrl's (#123,
// Acceptance 9). Outside the usage texts (const usage, keysUsage), no
// string in internal/cli or internal/ownerkey names sbxkey, sbxverify or
// sbxapi followed by one of their commands or a flag.
func TestNoToolNameInCommands(t *testing.T) {
	command := regexp.MustCompile(`\bsbx(key|verify|api) (-[a-z]|(init|restore|backup-check|start|unlock|new|rename|known-hosts|keys|recovery-key|exec|cp)\b)`)
	// Not commands: the marker lines of the shell prelude -env writes into
	// the setup script (env.go), which the TD's script reads as they are.
	allowed := map[string]bool{
		"keycmd/env.go: # sbxkey -env: end of prelude":                                                                                                                  true,
		"keycmd/env.go: # sbxkey -env (#75): the owner's environment variables, set at the first boot.\n":                                                               true,
		"keycmd/env.go: timeout 120 systemctl daemon-reexec || echo 'sbxkey -env: systemctl daemon-reexec failed; services see the variables from the next boot' >&2\n": true,
	}
	usageConst := map[string]bool{"usage": true, "keysUsage": true}
	var dirs []string
	for _, d := range []string{"keycmd", "verifycmd", "apicmd", filepath.Join("..", "ownerkey")} {
		dirs = append(dirs, filepath.Join("..", d))
	}
	seen := 0
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			seen++
			rel := filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(f)), filepath.Base(f)))
			ast.Inspect(file, func(n ast.Node) bool {
				if vs, ok := n.(*ast.ValueSpec); ok && len(vs.Names) == 1 && usageConst[vs.Names[0].Name] {
					return false
				}
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: %v", fset.Position(lit.Pos()), err)
				}
				if command.MatchString(s) && !allowed[rel+": "+s] {
					t.Errorf("%s: a command written with the tool's name, not through ownerkey.Command or prog: %q", fset.Position(lit.Pos()), s)
				}
				return true
			})
		}
	}
	if seen < 10 {
		t.Fatalf("only %d files read: the test does not look where it should", seen)
	}
}
