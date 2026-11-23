package keycmd

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

const promptTestKey = "sk-ant-api03-FAKE_test-key.0123456789"

// helperScript runs examples/prompt-setup.sh with args, the key (if any) on
// its standard input, its standard output a pipe, and returns what it prints.
func helperScript(t *testing.T, key string, args ...string) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	helper, err := filepath.Abs("../../../examples/prompt-setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	// From an empty directory, as tests/prompt-setup.sh runs it.
	cmd := exec.Command(sh, append([]string{helper}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Stdin = strings.NewReader(key + "\n")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("prompt-setup.sh %q: %v\n%s", args, err, errb.String())
	}
	return string(out)
}

// goScript is buildPrompt for p, the key given as one line on a pipe.
func goScript(t *testing.T, p promptOpts, key string) string {
	t.Helper()
	var errb bytes.Buffer
	s, err := buildPrompt(&p, bufio.NewReader(strings.NewReader(key+"\n")), false, &errb)
	if err != nil {
		t.Fatalf("buildPrompt %+v: %v", p, err)
	}
	if key != "" && strings.Contains(errb.String(), key) {
		t.Fatalf("the key was printed: %s", errb.String())
	}
	return s
}

// The script built in memory is byte for byte what examples/prompt-setup.sh
// prints for the same inputs: each agent with its key (pi with and without
// a provider), no key, a task from a file, and a task that holds quotes,
// $( ), backticks, a backslash and the helper's own end marker.
func TestPromptMatchesHelper(t *testing.T) {
	tricky := strings.Join([]string{`Write "hello" to a file; do not run $(rm -rf /) or ` + "`id`" + `.`, `a \n backslash`, "SBX_TASK_END", "SBX_TASK_END_", "it's done", "  indented\ttab"}, "\n")
	dir := t.TempDir()
	file := filepath.Join(dir, "task.md")
	// Trailing newlines are dropped, as $(cat FILE) drops them.
	if err := os.WriteFile(file, []byte("# Task\n\nbuild X, then\n  test it\n\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	trailing := "a task given with its own newline\n"
	for _, c := range []struct {
		name   string
		args   []string
		p      promptOpts
		key    string
		marker string
	}{
		{"claude", []string{"say hello"}, promptOpts{text: "say hello", textSet: true}, promptTestKey, ".claude/settings.json"},
		{"codex", []string{"--agent", "codex", tricky}, promptOpts{text: tricky, textSet: true, agent: "codex"}, promptTestKey, ".codex/auth.json"},
		{"pi", []string{"--agent", "pi", "say hello"}, promptOpts{text: "say hello", textSet: true, agent: "pi"}, promptTestKey, `{"anthropic": {`},
		{"pi provider", []string{"--agent", "pi", "--provider", "openai", tricky}, promptOpts{text: tricky, textSet: true, agent: "pi", provider: "openai"}, promptTestKey, `{"openai": {`},
		{"no key", []string{"--no-key", tricky}, promptOpts{text: tricky, textSet: true, noKey: true}, "", "SBX_TASK_END__"},
		{"no key codex", []string{"--agent", "codex", "--no-key", "x"}, promptOpts{text: "x", textSet: true, agent: "codex", noKey: true}, "", "codex exec"},
		{"prompt file", []string{"--file", file}, promptOpts{file: file}, promptTestKey, "  test it\nSBX_TASK_END\n"},
		{"prompt file pi", []string{"--agent", "pi", "--file", file}, promptOpts{file: file, agent: "pi"}, promptTestKey, "pi -p"},
		{"trailing newline", []string{trailing}, promptOpts{text: trailing, textSet: true}, promptTestKey, "newline\n\nSBX_TASK_END\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := helperScript(t, c.key, c.args...)
			got := goScript(t, c.p, c.key)
			if got != want {
				t.Fatalf("differs from the helper's output\ngot:\n%s\nwant:\n%s", got, want)
			}
			if !strings.Contains(got, c.marker) {
				t.Errorf("no %q in the script", c.marker)
			}
			if (c.key != "") != strings.Contains(got, promptTestKey) {
				t.Errorf("key in the script: %v, want %v", strings.Contains(got, promptTestKey), c.key != "")
			}
		})
	}
}

// A task over 8 KiB, from -prompt or -prompt-file, is refused with the
// helper's message, before any key is asked for; so is a script over
// proto.MaxSetupScript, here with a long key.
func TestPromptLimits(t *testing.T) {
	big := strings.Repeat("a", 9216)
	file := filepath.Join(t.TempDir(), "big.txt")
	if err := os.WriteFile(file, []byte(big+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]promptOpts{
		"-prompt":      {text: big, textSet: true},
		"-prompt-file": {file: file},
	} {
		var errb bytes.Buffer
		_, err := buildPrompt(&p, bufio.NewReader(strings.NewReader(promptTestKey+"\n")), false, &errb)
		if err == nil || err.Error() != "the task is 9217 bytes; at most 8192 (8 KiB): the setup script is limited to 10 KiB" {
			t.Errorf("%s: a 9 KiB task: %v", name, err)
		}
		if errb.Len() != 0 {
			t.Errorf("%s: asked for a key for a task that is refused: %q", name, errb.String())
		}
	}
	// Exactly 8192 with the newline: accepted, as by the helper.
	edge := strings.Repeat("b", maxPromptTask-1)
	if got, want := goScript(t, promptOpts{text: edge, textSet: true, noKey: true}, ""), helperScript(t, "", "--no-key", edge); got != want {
		t.Error("an 8 KiB task: differs from the helper")
	}
	if _, err := promptTask(&promptOpts{text: edge + "b", textSet: true}); err == nil {
		t.Error("8193 bytes accepted")
	}
	// The task fits; the key makes the whole too long.
	longKey := strings.Repeat("k", 3000)
	p := promptOpts{text: edge, textSet: true}
	_, err := buildPrompt(&p, bufio.NewReader(strings.NewReader(longKey+"\n")), false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "a setup script is at most 10240") || !strings.HasPrefix(err.Error(), "the script is ") {
		t.Errorf("a script over %d bytes: %v", proto.MaxSetupScript, err)
	}
	if err != nil && strings.Contains(err.Error(), longKey) {
		t.Error("the error shows the key")
	}
	// The helper refuses the same.
	cmd := exec.Command("sh", "../../../examples/prompt-setup.sh", edge)
	cmd.Stdin = strings.NewReader(longKey + "\n")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if out, err := cmd.Output(); err == nil || len(out) != 0 || !strings.Contains(errb.String(), "a setup script is at most 10240") {
		t.Errorf("the helper with the long key: %v, %d bytes, %s", err, len(out), errb.String())
	}
	// With -env, the prelude counts too: setupWithEnv over the prompt script.
	s := goScript(t, promptOpts{text: edge, textSet: true}, promptTestKey)
	if _, err := setupWithEnv([]string{"PAD=" + strings.Repeat("p", proto.MaxSetupScript-len(s))}, s, proto.MaxSetupScript); err == nil {
		t.Error("prompt script and -env over the limit accepted")
	}
	small := goScript(t, promptOpts{text: "say hello", textSet: true}, promptTestKey)
	if all, err := setupWithEnv([]string{"FOO=bar"}, small, proto.MaxSetupScript); err != nil || !strings.HasSuffix(all, envEndMarker+"\n"+small) {
		t.Errorf("prompt script and -env: %v", err)
	}
}

// What does not go together is refused, before any key is asked for.
func TestPromptFlagsRefused(t *testing.T) {
	for _, c := range []struct {
		name   string
		p      promptOpts
		isNew  bool
		script string
		want   string
	}{
		{"with -setup-script", promptOpts{text: "x", textSet: true}, true, "s.sh", "-prompt and -setup-script both given"},
		{"file with -setup-script", promptOpts{file: "t.md"}, true, "s.sh", "-prompt and -setup-script both given"},
		{"-prompt and -prompt-file", promptOpts{text: "x", textSet: true, file: "t.md"}, true, "", "-prompt and -prompt-file both given"},
		{"on start or unlock", promptOpts{text: "x", textSet: true}, false, "", "for new only"},
		{"-agent on unlock", promptOpts{agent: "codex", agentSet: true}, false, "", "for new only"},
		{"-agent alone", promptOpts{agent: "codex", agentSet: true}, true, "", "go with -prompt"},
	} {
		err := c.p.check(c.isNew, c.script)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := (&promptOpts{}).check(false, "s.sh"); err != nil {
		t.Errorf("no -prompt: %v", err)
	}
	if err := (&promptOpts{text: "x", textSet: true, agent: "pi", agentSet: true}).check(true, ""); err != nil {
		t.Errorf("-prompt -agent pi: %v", err)
	}
	for name, c := range map[string]struct {
		p    promptOpts
		key  string
		want string
	}{
		"empty task":       {promptOpts{textSet: true}, promptTestKey, "the task is empty"},
		"agent vim":        {promptOpts{text: "x", textSet: true, agent: "vim"}, promptTestKey, "-agent is claude, codex or pi, not 'vim'"},
		"provider codex":   {promptOpts{text: "x", textSet: true, agent: "codex", provider: "openai"}, promptTestKey, "-agent-provider is for -agent pi only"},
		"provider spelled": {promptOpts{text: "x", textSet: true, agent: "pi", provider: "Open AI"}, promptTestKey, "pi provider name"},
		"no key":           {promptOpts{text: "x", textSet: true}, "", "no key given"},
		"not a key":        {promptOpts{text: "x", textSet: true}, "sk ant;rm", "does not look like an API key"},
		"missing file":     {promptOpts{file: "/nonexistent/task.md"}, promptTestKey, "cannot read /nonexistent/task.md"},
	} {
		_, err := buildPrompt(&c.p, bufio.NewReader(strings.NewReader(c.key+"\n")), false, io.Discard)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The key from a pipe is one line: what follows it stays for the next
// reader, and a last line without a newline is read too.
func TestPromptKeyFromPipe(t *testing.T) {
	in := bufio.NewReader(strings.NewReader(promptTestKey + "\nnext line\n"))
	var errb bytes.Buffer
	k, err := readAgentKey("Anthropic API key", in, false, &errb)
	if err != nil || k != promptTestKey {
		t.Fatalf("%q, %v", k, err)
	}
	if rest, _ := in.ReadString('\n'); rest != "next line\n" {
		t.Errorf("read past the key's line: %q left", rest)
	}
	if errb.String() != "Anthropic API key (not shown): \n" {
		t.Errorf("prompt %q", errb.String())
	}
	if k, err := readAgentKey("x", bufio.NewReader(strings.NewReader(promptTestKey)), false, io.Discard); err != nil || k != promptTestKey {
		t.Errorf("no final newline: %q, %v", k, err)
	}
}
