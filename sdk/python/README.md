# trajrl-sdk: TrajRL's sandboxes from Python

The Python SDK for TrajRL's TDX sandboxes. It runs on your own machine and drives the `trajrl`
command line there, through its `--json` interface. You import it as `trajrl`.

```
pip install trajrl-sdk
```

Pure Python, no dependencies, Python 3.9 or later. The one thing it needs is `trajrl`.

## It needs trajrl

A sandbox's disk key, the check of its TD and the host keys pinned for it live only on your
machine, in `trajrl`. That is why this SDK is not an HTTP client of the platform: the platform
never holds what it takes to bring a sandbox up. The SDK runs `trajrl` for every call.

Install `trajrl`:

```
brew tap hanlinai/trajrl-cli https://github.com/hanlinai/trajrl-cli && brew install trajrl   # macOS, Linux
curl -fsSL https://sandbox.trajrl.com/trajrl/install.sh | sh                                 # Linux, macOS
scoop bucket add trajrl https://github.com/hanlinai/trajrl-cli; scoop install trajrl          # Windows
```

then `trajrl setup` once, with the line from the website's Settings page. The SDK finds `trajrl`
as the `trajrl_bin=` argument, else `$TRAJRL_BIN`, else on `PATH`, and checks it with
`trajrl version --json`.

**Run it where your key is.** Unlocking a sandbox (`create`, `start`, `unlock`) uses your disk
key, so it runs on the machine that holds it: yours, or one you trust with that key. `trajrl`
never prompts here. It reads the key file's passphrase from the file named by
`passphrase_file=` or `$TRAJRL_PASSPHRASE_FILE`.

## Quickstart

```python
from trajrl import Client

c = Client()                       # or Client(trajrl_bin=..., passphrase_file=..., timeout=...)
print(c.version)                   # trajrl's version
print(c.status())                  # your sandboxes, what this machine verified, what to run next

sb = c.sandboxes.create("web", size="small")   # create, verify its TD, unlock its first boot
sb = c.sandboxes.get("web")
for s in c.sandboxes.list():
    print(s.name, s.state)

print(sb.verify()["verdict"])      # VERIFIED, or NotVerified is raised

r = sb.exec(["uname", "-a"])       # a list of words, run without a shell
print(r.exit_code, r.stdout.decode())

for kind, data in sb.exec_stream(["sh", "-c", "for i in 1 2 3; do echo $i; sleep 1; done"]):
    print(kind, data)              # ("stdout", b"1\n") ... ("exit", 0)

sb.upload("app.tar", "/root/app.tar")       # bytes copied
sb.download("/var/log/syslog", "syslog")

sb.stop(); sb.start(); sb.wait()
sb.remove()                        # for good
```

The API:

| Call | trajrl command | Returns |
| --- | --- | --- |
| `Client(trajrl_bin=None, passphrase_file=None, timeout=None)` | `version --json` | the client; `.version`, `.min_entry` |
| `c.status()` | `status --json` | dict (a machine not set up: `configured` false) |
| `c.doctor()` | `doctor --json` | `{"ok", "checks"}`; failing checks are in it, not raised |
| `c.sandboxes.list()` | `ls --json` | `[Sandbox]` |
| `c.sandboxes.get(name)` | `show NAME --json` | `Sandbox` |
| `c.sandboxes.create(name, size=None, disk=None, image=None)` | `new NAME ... --json` | `Sandbox`, `.last_boot` the answer |
| `sb.name`, `sb.state`, `sb.id`, `sb.data`, `sb.refresh()` | `show NAME --json` | what the platform says |
| `sb.start()`, `sb.unlock()` | `start`/`unlock NAME --json` | `{"name", "state", "verified", "host_key_sha256", "boot"}` |
| `sb.stop()`, `sb.wait(timeout=None)` | `stop`/`wait NAME --json` | the sandbox, as a dict |
| `sb.remove()` | `rm NAME --yes --json` | `{"removed": NAME, ...}` |
| `sb.verify()` | `verify NAME --json` | the verdict; anything but VERIFIED raises `NotVerified` |
| `sb.exec(argv, cwd=None, env=None, stdin=None, timeout=None)` | `exec NAME --json ... -- ARGV` | `ExecResult(stdout, stderr, exit_code, error)` |
| `sb.exec_stream(argv, ...)` | the same | `ExecEvent`s: `("stdout"\|"stderr", bytes)`, `("error", str)`, then `("exit", int)` |
| `sb.upload(local, remote)`, `sb.download(remote, local)` | `cp ... --json` | bytes copied |

Right after `create`, `start` or `unlock`, `state` is often still `starting`: `sb.wait()` waits
until it runs. `exec` and `cp` reach the sandbox with the host key `trajrl` pinned for it on this
machine (by the unlock, or `trajrl verify`); without one they fail with `CommandFailed`.

`exec`'s `timeout` is the command's own limit in seconds (trajrl's default 60, at most 300); its
`stdin` (bytes or str) is sent whole before the command starts. The client's `timeout` is the time
limit of each `trajrl` call; leave it `None` for `create` and `start`, which can take minutes.

## Errors

Every exception is a `TrajrlError`, with `.message`, `.code` (trajrl's exit status), `.stderr`,
`.error_code` (the `code` of trajrl's JSON error), `.result` (its JSON stdout, if it printed one
anyway) and `.argv`.

| Exception | When |
| --- | --- |
| `TrajrlNotFound` | no `trajrl`, or the program found does not answer `version --json` |
| `UsageError` | exit status 2: trajrl refused the command line |
| `NeedsOwner` | exit status 3: the passphrase is missing, or the sandbox waits for your key (`sb.unlock()`) |
| `TransportError` | exit status 255: the platform or the sandbox not reached, the connection cut; or the call's timeout |
| `CommandFailed` | exit status 1, or another failure of a command trajrl forwards to the platform |
| `SandboxNotFound`, `SandboxNotRunning` | `CommandFailed`, when the platform says so |
| `NotVerified` | `CommandFailed`: `verify` did not vouch for the sandbox; `.result` is the verdict |

`exec` does not raise when the command exits non-zero: the exit code is in the result.

## What it does not do

It never handles a key. It reads no key file, asks for no passphrase and keeps no pinned host
key: `trajrl` does all of that, on this machine, as it does on the command line. The SDK only
passes on where the passphrase file is. Every call is one `trajrl` process started with a list of
arguments, never through a shell, with stdin closed unless you give `exec` some.

## Tests

```
python -m pytest            # against a fake trajrl (tests/fake_trajrl.py)
TRAJRL_SMOKE=1 python -m pytest tests/test_smoke_stage.py -s   # read-only, with your real trajrl
```
