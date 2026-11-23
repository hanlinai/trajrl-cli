#!/bin/sh
# A new sandbox that starts a coding agent on a task at its first boot (#70):
#   examples/prompt-setup.sh 'build X' > s.sh && sbxkey new -setup-script s.sh NAME && rm s.sh
#   examples/prompt-setup.sh --agent codex --file task.md > s.sh   (then the same)
# Prints a first-boot setup script (POSIX sh) for sbxkey new -setup-script. In
# the sandbox, run once as root by tdx-sandbox-setup.service, it
#   - writes the task to /home/dev/task/prompt.txt, and the key into dev's
#     settings for that agent, mode 0600;
#   - starts the agent as dev, without a terminal, in the transient unit
#     sandbox-task (systemd-run --uid=dev), in /home/dev/task, the task on its
#     standard input: claude -p, codex exec, pi -p;
#   - sends its output to /home/dev/task/log and its exit code to
#     /home/dev/task/exit (absent while it runs).
# Read the log with ssh dev@NAME tail -f task/log; systemctl status sandbox-task
# says whether it still runs. See docs/agents.md, "Create a sandbox with a task".
#
# The agent runs with its permission prompts off (claude
# --dangerously-skip-permissions, codex --dangerously-bypass-approvals-and-sandbox;
# pi asks none): nobody is there to answer them. The sandbox is the boundary,
# and dev has sudo in it.
#
# Options:
#   --agent claude|codex|pi  the agent (default claude)
#   --file FILE              the task from FILE instead of an argument
#   --no-key                 put no key in; add one later (docs/agents.md, #68)
#   --provider NAME          pi only: the provider the key is for (default anthropic)
#   --agent-cmd CMD          tests only: run the shell command CMD, with the
#                            prompt file as $1, instead of the agent
# The key is read from standard input, not shown on a terminal: Claude Code's
# ANTHROPIC_API_KEY, Codex's OpenAI API key, or pi's key for --provider. The
# task is at most 8 KiB: the whole script must fit in a setup script's 10 KiB
# (proto.MaxSetupScript).
#
# sbxkey sends the script to the sandbox encrypted to a key the sandbox's
# attestation vouches for: the platform sees neither the task nor the key. Do
# not give it to the entry point's own "new --setup-script -": that copy is
# kept by the platform. s.sh holds the key in clear on this machine: it is made
# 0600 here (on Linux), and you delete it once sbxkey new has run. The script
# ends without an exit: your own setup can be appended (cat my.sh >> s.sh; it
# then runs under sh after set -eu), within the 10 KiB.
usage='usage: prompt-setup.sh [--agent claude|codex|pi] [--no-key] [--provider NAME] (--file FILE | TASK) > s.sh'
agent=claude file= nokey= provider= cmd=
while [ $# -gt 0 ]; do
	case $1 in
	--agent|--file|--provider|--agent-cmd) [ $# -ge 2 ] || { echo "$usage" >&2; exit 2; } ;;
	esac
	case $1 in
	--agent) agent=$2; shift 2 ;;
	--file) file=$2; shift 2 ;;
	--provider) provider=$2; shift 2 ;;
	--agent-cmd) cmd=$2; shift 2 ;;
	--no-key) nokey=1; shift ;;
	-h|--help) echo "$usage"; exit 0 ;;
	--) shift; break ;;
	-*) echo "$usage" >&2; exit 2 ;;
	*) break ;;
	esac
done
case $agent in
claude) run='claude -p --dangerously-skip-permissions <"$1"' ;;
codex) run='codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check - <"$1"' ;;
pi) run='pi -p <"$1"' ;;
*) echo "--agent is claude, codex or pi, not '$agent'" >&2; exit 2 ;;
esac
if [ -n "$provider" ]; then
	[ "$agent" = pi ] || { echo "--provider is for --agent pi only" >&2; exit 2; }
	case $provider in *[!a-z0-9-]*) echo "--provider is a pi provider name, such as anthropic or openai" >&2; exit 2 ;; esac
fi
provider=${provider:-anthropic}
if [ -n "$cmd" ]; then
	case $cmd in *'
'*) echo "--agent-cmd is one line" >&2; exit 2 ;; esac
	run=$cmd
fi
if [ -n "$file" ]; then
	[ $# -eq 0 ] || { echo "$usage" >&2; exit 2; }
	[ -r "$file" ] || { echo "cannot read $file" >&2; exit 1; }
	task=$(cat "$file") || exit 1
else
	[ $# -eq 1 ] || { echo "$usage" >&2; exit 2; }
	task=$1
fi
[ -n "$task" ] || { echo "the task is empty" >&2; exit 1; }
n=$(printf '%s\n' "$task" | wc -c)
[ "$n" -le 8192 ] || { echo "the task is $n bytes; at most 8192 (8 KiB): the setup script is limited to 10 KiB" >&2; exit 1; }
# The task goes into a quoted here-document, whose end line it must not hold.
eot=SBX_TASK_END
while printf '%s\n' "$task" | grep -qx "$eot"; do eot=${eot}_; done

umask 077
if [ -t 1 ]; then echo "send the output to a file: prompt-setup.sh ... > s.sh (it holds the task and the key)" >&2; exit 2; fi
# The key never goes to a file anyone else can read, even for a moment.
if [ -f /dev/stdout ] && ! chmod 600 /dev/stdout 2>/dev/null; then
	echo "could not make the output file 0600; nothing was written" >&2; exit 1
fi
key=
if [ -z "$nokey" ]; then
	case $agent in claude) what='Anthropic API key' ;; codex) what='OpenAI API key' ;; pi) what="API key for pi's provider $provider" ;; esac
	printf '%s (not shown): ' "$what" >&2
	if [ -t 0 ]; then stty -echo; IFS= read -r key; stty echo; echo >&2; else IFS= read -r key || :; echo >&2; fi
	[ -n "$key" ] || { echo "no key given (--no-key to add one later)" >&2; exit 1; }
	case $key in *[!A-Za-z0-9._-]*) echo "that does not look like an API key" >&2; exit 1 ;; esac
fi

# The script, built here and printed whole once it is known to fit.
s=$(
cat <<'EOF'
#!/bin/sh
# A task for a coding agent at the first boot (examples/prompt-setup.sh, #70).
# Runs once, as root. Prints neither the task nor a key.
set -eu
id dev >/dev/null 2>&1 || { echo "prompt-setup: this image has no user dev (image revision 9 on)" >&2; exit 1; }
h=$(getent passwd dev | cut -d: -f6)
umask 077
mkdir -p "$h/task"
EOF
printf "cat >\"\$h/task/prompt.txt\" <<'%s'\n%s\n%s\n" "$eot" "$task" "$eot"
if [ -n "$key" ]; then
	case $agent in
	claude) d=.claude f=settings.json j="{\"env\": {\"ANTHROPIC_API_KEY\": \"$key\", \"SBX_LLM_ROUTE\": \"provider\"}}" ;;
	codex) d=.codex f=auth.json j="{\"auth_mode\": \"apikey\", \"OPENAI_API_KEY\": \"$key\"}" ;;
	pi) d=.pi/agent f=auth.json j="{\"$provider\": {\"type\": \"api_key\", \"key\": \"$key\"}}" ;;
	esac
	printf 'mkdir -p "$h/%s"\n' "$d"
	printf "cat >\"\$h/%s/%s\" <<'SBX_AGENT_KEY'\n%s\nSBX_AGENT_KEY\n" "$d" "$f" "$j"
	printf 'chmod 600 "$h/%s/%s"; chown -R dev:dev "$h/%s"\n' "$d" "$f" "${d%%/*}"
fi
printf "cat >\"\$h/task/run\" <<'SBX_TASK_RUN'\n"
cat <<'EOF'
#!/bin/bash -l
# The first-boot task (examples/prompt-setup.sh, #70): the agent on prompt.txt,
# as dev, its output in log and its exit code in exit.
cd "${0%/*}" || exit 1
set -- "$PWD/prompt.txt"
rm -f exit
{
EOF
printf '%s\n' "$run"
cat <<'EOF'
} >log 2>&1 </dev/null
rc=$?; echo "$rc" >exit; exit "$rc"
SBX_TASK_RUN
chmod 700 "$h/task/run"; chown -R dev:dev "$h/task"
systemd-run --quiet --uid=dev --unit=sandbox-task --working-directory="$h/task" --remain-after-exit \
	--setenv=HOME="$h" --description="first-boot task (prompt-setup)" "$h/task/run"
echo "prompt-setup: the task runs as dev in unit sandbox-task; output in $h/task/log"
EOF
)
size=$(printf '%s\n' "$s" | wc -c)
[ "$size" -le 10240 ] || { echo "the script is $size bytes; a setup script is at most 10240" >&2; exit 1; }
printf '%s\n' "$s"
if [ -n "$key" ]; then echo "Written. Delete the file once sbxkey new has run: it holds your key." >&2; fi
