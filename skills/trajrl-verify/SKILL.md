---
name: trajrl-verify
description: Verify a TrajRL sandbox from the owner's machine with trajrl verify, and read its VERIFIED, NOT VERIFIED and REFUSED results. Use when checking that a sandbox is a genuine TDX guest running the expected image, or when one of those words is in the output of trajrl.
---

# Verifying a TrajRL sandbox

`trajrl verify` checks a running sandbox from this machine, trusting nothing the platform says:
Intel's signature on the TD's quote, every TCB level rated UpToDate, the measurements against the
owner's launch policies, this sandbox's identity, a fresh nonce, and that the SSH session it used
ends inside the TD. On success it records the TD's host key, which `trajrl ssh`, `exec` and `cp`
then accept.

## Rules

- **Secrets stay unseen.** Key files, recovery phrases, passphrase files and SSH private keys are
  read only by `trajrl` itself. Pass their paths; leave their contents unopened and unprinted.
- **Ask the human first, every time**, and wait for a clear yes, before running anything with one
  of: `rm NAME --yes`, `-accept-older N`, `-accept-newer N`, `-accept-recovered`, `-first-boot`,
  `rollback-accept NAME --yes`. A verdict is never a reason to skip that.
- **No interactive screen.** Never run `trajrl` with no arguments or `trajrl tui`; `trajrl status
  --json` says which sandboxes this machine has verified (`verified_host_key`, `last_verified`).
- A verdict is final. There is no flag that relaxes a check; report what failed instead.

## Run it

| Task | Command |
|---|---|
| one sandbox | `trajrl verify NAME --json` |
| also that the owner's key unlocked it (asks the passphrase) | `trajrl verify NAME -owner --json` |
| every running sandbox; exit 1 if any fails | `trajrl verify --all` |
| the same with the owner check | `trajrl verify --all -owner -passphrase-file FILE` |
| the launch policies used (none given: all of them) | `trajrl policy list` |

With `--json`, standard output is one object: `verdict` (`VERIFIED` or `NOT VERIFIED`), `reason`
(why not), `sandbox_id`, `checked_at`, `quote` (Intel's rating and the measurements),
`unlocked_by_owner`, `image`. The account for people goes to standard error. Exit status 0 means
`VERIFIED`.

## Reading the result

- **`VERIFIED`**: every check held. It says the sandbox is that TD, running the image of a policy
  the owner accepts, with the host key recorded here. `unlocked_by_owner: true` (with `-owner`)
  adds that the owner's key unlocked its disk. A note that the service lists another host key
  means the platform's list is wrong, not the TD: trust the verified key.
- **`NOT VERIFIED`**: at least one check failed and `reason` says which. Treat the sandbox as
  unknown: send it no secrets and no data. Common reasons: no policy matches the measurements
  (the image changed: `trajrl policy add FILE` only with a policy file the human trusts); a TCB
  level not UpToDate (the platform's to fix); the sandbox not running (`trajrl show NAME --json`).
  `REHEARSAL, NOT VERIFIED` comes from a test build only, never from a real one.
- **`REFUSED`** (from `new`, `start` or `unlock`, not from `verify`): the TD passed, but the disk
  it was given is not the one on the owner's record (an older or newer copy, a blank disk, another
  image), so the key was withheld and the sandbox stops. The message ends with the one command
  that would accept that disk. Give the human the message and that command; it runs only on their
  explicit yes.
