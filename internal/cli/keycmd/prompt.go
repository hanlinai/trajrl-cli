package keycmd

// sbxkey new -prompt TEXT | -prompt-file FILE (#111): a new sandbox that
// starts a coding agent on a task at its first boot, as
// examples/prompt-setup.sh does, but with the setup script built here, in
// memory. The provider key is read without echo (or as one line from a pipe)
// and goes from this process into the encrypted first-boot session: it never
// sits in a local file, even for a moment.
//
// The script is byte for byte what examples/prompt-setup.sh prints for the
// same task, agent, provider and key (TestPromptMatchesHelper). The helper
// stays the reference; docs/agents.md, "Create a sandbox with a task", says
// what the script does in the sandbox.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// maxPromptTask is the most a task may be, its final newline counted: the
// helper's 8 KiB, so that the whole script fits in proto.MaxSetupScript.
const maxPromptTask = 8192

// promptOpts are new's -prompt, -prompt-file, -agent, -agent-provider and
// -no-agent-key.
type promptOpts struct {
	text, file      string
	agent, provider string
	noKey           bool
	// textSet: -prompt was given (even empty); agentSet: one of -agent,
	// -agent-provider, -no-agent-key was.
	textSet, agentSet bool
}

func (p *promptOpts) given() bool { return p.textSet || p.file != "" }

// check refuses what does not go together: start and unlock take none of
// these, -prompt and -prompt-file exclude each other and -setup-script, and
// the agent flags need one of them.
func (p *promptOpts) check(isNew bool, setupScript string) error {
	if !p.given() && !p.agentSet {
		return nil
	}
	if !isNew {
		return errors.New("-prompt, -prompt-file, -agent, -agent-provider and -no-agent-key are for new only: the task starts at a sandbox's first boot")
	}
	if !p.given() {
		return errors.New("-agent, -agent-provider and -no-agent-key go with -prompt or -prompt-file")
	}
	if p.textSet && p.file != "" {
		return errors.New("-prompt and -prompt-file both given; the task is one of them")
	}
	if setupScript != "" {
		return errors.New("-prompt and -setup-script both given: -prompt builds the setup script (examples/prompt-setup.sh ... > s.sh and -setup-script s.sh to add your own to it)")
	}
	return nil
}

// agentRun is each agent's command line in the task's run script, the
// prompt file as $1 on its standard input.
var agentRun = map[string]string{
	"claude": `claude -p --dangerously-skip-permissions <"$1"`,
	"codex":  `codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check - <"$1"`,
	"pi":     `pi -p <"$1"`,
}

// agentAndProvider checks -agent and -agent-provider as the helper checks
// --agent and --provider, and fills in their defaults.
func agentAndProvider(agent, provider string) (string, string, error) {
	if agent == "" {
		agent = "claude"
	}
	if _, ok := agentRun[agent]; !ok {
		return "", "", fmt.Errorf("-agent is claude, codex or pi, not '%s'", agent)
	}
	if provider != "" {
		if agent != "pi" {
			return "", "", errors.New("-agent-provider is for -agent pi only")
		}
		if strings.IndexFunc(provider, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') }) >= 0 {
			return "", "", errors.New("-agent-provider is a pi provider name, such as anthropic or openai")
		}
	}
	if provider == "" {
		provider = "anthropic"
	}
	return agent, provider, nil
}

// promptTask is the task: -prompt as given, or -prompt-file's content with
// its trailing newlines taken off (as the helper's $(cat FILE) does). At most
// maxPromptTask bytes with a final newline, the helper's message otherwise.
func promptTask(p *promptOpts) (string, error) {
	task := p.text
	if p.file != "" {
		b, err := os.ReadFile(p.file)
		if err != nil {
			return "", fmt.Errorf("cannot read %s: %w", p.file, err)
		}
		task = strings.TrimRight(string(b), "\n")
	}
	if task == "" {
		return "", errors.New("the task is empty")
	}
	if strings.IndexByte(task, 0) >= 0 {
		return "", errors.New("the task holds a NUL byte; it is text")
	}
	if n := len(task) + 1; n > maxPromptTask {
		return "", fmt.Errorf("the task is %d bytes; at most %d (8 KiB): the setup script is limited to 10 KiB", n, maxPromptTask)
	}
	return task, nil
}

// keyWhat is how the helper names each agent's key when it asks for it.
func keyWhat(agent, provider string) string {
	switch agent {
	case "codex":
		return "OpenAI API key"
	case "pi":
		return "API key for pi's provider " + provider
	}
	return "Anthropic API key"
}

// readAgentKey asks for the key on stderr and reads it: from the terminal
// without echo, or else one line from in. The key is checked as the helper
// checks it and never printed.
func readAgentKey(what string, in *bufio.Reader, tty bool, errw io.Writer) (string, error) {
	fmt.Fprintf(errw, "%s (not shown): ", what)
	var key string
	if tty {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(errw)
		if err != nil {
			return "", err
		}
		key = string(b)
	} else {
		s, err := in.ReadString('\n')
		fmt.Fprintln(errw)
		if err != nil && err != io.EOF {
			return "", err
		}
		key = strings.TrimSuffix(s, "\n")
	}
	if key == "" {
		return "", errors.New("no key given (-no-agent-key to add one later)")
	}
	if strings.IndexFunc(key, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
	}) >= 0 {
		return "", errors.New("that does not look like an API key")
	}
	return key, nil
}

// The fixed parts of the script, as the helper's here-documents hold them.
const (
	promptHead = `#!/bin/sh
# A task for a coding agent at the first boot (examples/prompt-setup.sh, #70).
# Runs once, as root. Prints neither the task nor a key.
set -eu
id dev >/dev/null 2>&1 || { echo "prompt-setup: this image has no user dev (image revision 9 on)" >&2; exit 1; }
h=$(getent passwd dev | cut -d: -f6)
umask 077
mkdir -p "$h/task"
`
	promptRunHead = `cat >"$h/task/run" <<'SBX_TASK_RUN'
#!/bin/bash -l
# The first-boot task (examples/prompt-setup.sh, #70): the agent on prompt.txt,
# as dev, its output in log and its exit code in exit.
cd "${0%/*}" || exit 1
set -- "$PWD/prompt.txt"
rm -f exit
{
`
	promptRunTail = `} >log 2>&1 </dev/null
rc=$?; echo "$rc" >exit; exit "$rc"
SBX_TASK_RUN
chmod 700 "$h/task/run"; chown -R dev:dev "$h/task"
systemd-run --quiet --uid=dev --unit=sandbox-task --working-directory="$h/task" --remain-after-exit \
	--setenv=HOME="$h" --description="first-boot task (prompt-setup)" "$h/task/run"
echo "prompt-setup: the task runs as dev in unit sandbox-task; output in $h/task/log"
`
)

// promptScript is the first-boot setup script for task, agent and provider
// (checked by agentAndProvider), with key, or with no key for "": what
// examples/prompt-setup.sh prints. Refused over proto.MaxSetupScript.
func promptScript(agent, provider, task, key string) (string, error) {
	// The task goes into a quoted here-document, whose end line it must not hold.
	eot := "SBX_TASK_END"
	lines := strings.Split(task, "\n")
	for holds := true; holds; {
		holds = false
		for _, l := range lines {
			if l == eot {
				eot += "_"
				holds = true
				break
			}
		}
	}
	var b strings.Builder
	b.WriteString(promptHead)
	fmt.Fprintf(&b, "cat >\"$h/task/prompt.txt\" <<'%s'\n%s\n%s\n", eot, task, eot)
	if key != "" {
		var d, f, j string
		switch agent {
		case "claude":
			d, f, j = ".claude", "settings.json", `{"env": {"ANTHROPIC_API_KEY": "`+key+`", "SBX_LLM_ROUTE": "provider"}}`
		case "codex":
			d, f, j = ".codex", "auth.json", `{"auth_mode": "apikey", "OPENAI_API_KEY": "`+key+`"}`
		case "pi":
			d, f, j = ".pi/agent", "auth.json", `{"`+provider+`": {"type": "api_key", "key": "`+key+`"}}`
		}
		top, _, _ := strings.Cut(d, "/")
		fmt.Fprintf(&b, "mkdir -p \"$h/%s\"\n", d)
		fmt.Fprintf(&b, "cat >\"$h/%s/%s\" <<'SBX_AGENT_KEY'\n%s\nSBX_AGENT_KEY\n", d, f, j)
		fmt.Fprintf(&b, "chmod 600 \"$h/%s/%s\"; chown -R dev:dev \"$h/%s\"\n", d, f, top)
	}
	b.WriteString(promptRunHead)
	b.WriteString(agentRun[agent] + "\n")
	b.WriteString(promptRunTail)
	s := b.String()
	if len(s) > proto.MaxSetupScript {
		return "", fmt.Errorf("the script is %d bytes; a setup script is at most %d", len(s), proto.MaxSetupScript)
	}
	return s, nil
}

// buildPrompt is the setup script for new -prompt: the flags checked, the
// task read, then the key asked for (unless -no-agent-key).
func buildPrompt(p *promptOpts, in *bufio.Reader, tty bool, errw io.Writer) (string, error) {
	agent, provider, err := agentAndProvider(p.agent, p.provider)
	if err != nil {
		return "", err
	}
	task, err := promptTask(p)
	if err != nil {
		return "", err
	}
	var key string
	if !p.noKey {
		if key, err = readAgentKey(keyWhat(agent, provider), in, tty, errw); err != nil {
			return "", err
		}
	}
	return promptScript(agent, provider, task, key)
}
