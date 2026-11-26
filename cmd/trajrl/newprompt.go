package main

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/cli/keycmd"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// published is the platform's launch policies this trajrl carries:
// policies/rev<N>/<model>/<size>.json, as tests/policy-publish.py lays them
// out, released with the binary that is built from the same tree.
//
//go:embed all:policies
var published embed.FS

// newFirst asks, before "new", what a first sandbox on this machine needs:
// which image, a disk key, the launch policies. Enter takes the default.
// Without a terminal, with --json or with -y/--yes, the defaults are taken
// without asking, and a disk key is not made (it needs a passphrase). It
// returns the arguments for new, -y/--yes taken out.
func newFirst(args []string) []string {
	yes := false
	out := args[:1:1]
	for _, a := range args[1:] {
		if a == "-y" || a == "--yes" {
			yes = true
			continue
		}
		out = append(out, a)
	}
	args = out
	if helpAsked(args) {
		return args
	}
	ask := !yes && interactive() && !clierr.WantsJSON(args[1:])

	if ask && !givenFlag(args, "image") {
		if choose("Image:", []string{"TrajRL system image", "Your own container image (REGISTRY/REPO@sha256:...)"}) == 1 {
			for {
				ref := askLine("Image, by digest (REGISTRY/REPO@sha256:...): ")
				if strings.Contains(ref, "/") && strings.Contains(ref, "@sha256:") {
					args = append([]string{args[0], "-image", ref}, args[1:]...)
					break
				}
				fmt.Fprintln(os.Stderr, "  name it by its digest, e.g. ghcr.io/you/app@sha256:4f2a...")
			}
		}
	}

	dir := flagValue(args, "dir")
	if dir == "" {
		dir = keycmd.DefaultDir()
	}
	if _, err := os.Stat(ownerkey.KeyFileIn(dir)); errors.Is(err, os.ErrNotExist) {
		if !ask || !yesNo("This machine has no disk key yet. Make one now?") {
			os.Exit(fail(1, "this machine has no disk key yet: run %s new NAME in a terminal, which makes one, or %s key init (or %s key restore, from your recovery phrase)", prog, prog, prog))
		}
		ki := []string{"key", "init"}
		if flagValue(args, "dir") != "" {
			ki = append(ki, "-dir", dir)
		}
		if pf := flagValue(args, "passphrase-file"); pf != "" {
			ki = append(ki, "-passphrase-file", pf)
		}
		keyCmd(ki)
		fmt.Fprintln(os.Stderr)
	}

	if !givenFlag(args, "policy") {
		if have, _ := policies(); len(have) == 0 {
			files := publishedPolicies()
			switch {
			case len(files) == 0:
				fmt.Fprintf(os.Stderr, "This %s carries no published launch policy yet: add the one you accept with %s policy add FILE.\n", prog, prog)
			case !ask || yesNo(fmt.Sprintf("No launch policy yet. Accept TrajRL's published policies (%d, carried by this %s)?", len(files), prog)):
				if err := addPublished(files); err != nil {
					fail(0, "%v", err)
				}
			}
		}
	}
	return args
}

// publishedPolicies are the paths of the policies this trajrl carries.
func publishedPolicies() []string {
	var files []string
	fs.WalkDir(published, "policies", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
			files = append(files, p)
		}
		return nil
	})
	return files
}

// addPublished puts the carried policies in the policy directory, each as
// rev<N>-<model>-<size>.json.
func addPublished(files []string) error {
	if err := os.MkdirAll(policyDir(), 0o700); err != nil {
		return err
	}
	for _, f := range files {
		b, err := published.ReadFile(f)
		if err != nil {
			return err
		}
		name := strings.ReplaceAll(strings.TrimPrefix(f, "policies/"), "/", "-")
		dst := filepath.Join(policyDir(), name)
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return err
		}
		if _, err := attest.LoadPolicy(dst); err != nil {
			os.Remove(dst)
			return fmt.Errorf("the carried policy %s: %v", f, err)
		}
	}
	fmt.Fprintf(os.Stderr, "Accepted %d published launch policies (%s policy list shows them).\n", len(files), prog)
	return nil
}

// choose asks for one of options by number; Enter is the first.
func choose(q string, options []string) int {
	fmt.Fprintln(os.Stderr, q)
	for i, o := range options {
		def := ""
		if i == 0 {
			def = " (default)"
		}
		fmt.Fprintf(os.Stderr, "  %d) %s%s\n", i+1, o, def)
	}
	for {
		a := askLine("Choose [1]: ")
		if a == "" {
			return 0
		}
		for i := range options {
			if a == fmt.Sprint(i+1) {
				return i
			}
		}
	}
}

// yesNo asks a question whose default is yes.
func yesNo(q string) bool {
	for {
		switch strings.ToLower(askLine(q + " [Y/n]: ")) {
		case "", "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}

// askLine reads one line from stdin a byte at a time, so that nothing
// after it is taken from what the passphrase prompts read.
func askLine(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(one)
		if n == 1 && one[0] != '\n' {
			b = append(b, one[0])
			continue
		}
		if n == 1 || err != nil {
			if err != nil && len(b) == 0 {
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			}
			return strings.TrimSpace(string(b))
		}
	}
}

// givenFlag tells whether -name or --name (=VALUE or not) is among args.
func givenFlag(args []string, name string) bool {
	for _, a := range args[1:] {
		f, _, _ := strings.Cut(a, "=")
		if f == "-"+name || f == "--"+name {
			return true
		}
	}
	return false
}

// flagValue is the value of -name VALUE or -name=VALUE among args.
func flagValue(args []string, name string) string {
	for i, a := range args[1:] {
		f, v, has := strings.Cut(a, "=")
		if f != "-"+name && f != "--"+name {
			continue
		}
		if has {
			return v
		}
		if i+2 < len(args) {
			return args[i+2]
		}
	}
	return ""
}

func helpAsked(args []string) bool {
	return givenFlag(args, "h") || givenFlag(args, "help") || len(args) == 1
}
