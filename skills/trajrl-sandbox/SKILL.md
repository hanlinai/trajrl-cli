---
name: trajrl-sandbox
description: Operate TrajRL sandboxes with the trajrl CLI. Use when creating, unlocking, listing, stopping or deleting a sandbox, logging in or running a command in one (ssh, exec, cp), sharing it on the web, setting its egress, or taking and restoring snapshots.
---

# Operating TrajRL sandboxes with trajrl

A TrajRL sandbox is a VM in an Intel TDX trust domain. Its owner holds its disk key; `trajrl`, on
the owner's machine, checks the TD and hands it the key. Every word `trajrl` does not know is the
platform's entry point's command, run there as it is (`trajrl help` lists the local ones).

## Rules

These hold for every command below, with no exception:

- **Secrets stay unseen.** The owner's key file (`owner.key` in sbxkey's directory), recovery
  phrase, passphrase files, SSH private keys and `-registry-auth` files are read only by `trajrl`
  itself. Pass their paths; leave their contents unopened and unprinted.
- **Ask the human first, every time**, and wait for a clear yes about this sandbox, before running
  anything with one of: `rm NAME --yes`, `-accept-older N`, `-accept-newer N`,
  `-accept-recovered`, `-first-boot`, `rollback-accept NAME --yes`. Each one destroys data or
  accepts a disk the tool would otherwise refuse. Show the human the exact command and the
  message that suggested it.
- **No interactive screen.** Never run `trajrl` with no arguments or `trajrl tui` (the screen is for
  people); read `trajrl status --json`, whose `next` is the command to run next, and run commands.
- **JSON for reading.** Add `--json` to every entry point command (`ls`, `show`, `stop`, ...) and
  parse that; the plain text is for people and changes.
- Commands that ask for a passphrase (`new`, `start`, `unlock`, `verify -owner`) need the human at
  the terminal, or a `-passphrase-file FILE` the human named.

## Set up once

The human pastes the line from the website's Settings, `trajrl setup -entry HOST:PORT -entry-key
'ssh-ed25519 ...'`. `trajrl whoami --json` then answers; if it does not, run that setup line.

## Sandboxes

| Task | Command |
|---|---|
| list | `trajrl ls --json` |
| one sandbox: state, size, `https_url`, `ssh_command` | `trajrl show NAME --json` |
| sizes and images there are | `trajrl sizes --json`, `trajrl images --json` |
| create (verifies the TD, unlocks the first boot) | `trajrl new NAME [--size S] [--image I]` |
| start a stopped one, or unlock one in state `waiting for its owner's key` | `trajrl start NAME`, `trajrl unlock NAME` |
| wait until running | `trajrl wait NAME --json` |
| stop, restart | `trajrl stop NAME --json`, `trajrl restart NAME --json` |
| rename | `trajrl rename OLD NEW` |
| delete for good (ask first) | `trajrl rm NAME --yes --json` |
| why it does not come up | `trajrl show NAME --log --json` |

A start or unlock that ends in `REFUSED` stops the sandbox and prints the one command that would
accept it. Report the message to the human; it is theirs to decide (rules above). The
`trajrl-verify` skill explains the verdicts.

## Inside a sandbox

- `trajrl ssh NAME -- COMMAND` logs in with the host key verified on this machine.
- `trajrl exec [-cwd DIR] [-e K=V] [-stdin] [-timeout SECONDS] NAME -- COMMAND [ARG...]` runs one
  command over the sandbox's HTTPS API; its exit status is the command's. Flags go before NAME.
- `trajrl cp LOCAL NAME:/PATH` and `trajrl cp NAME:/PATH LOCAL` copy one file.

All three accept only a host key verified here. Refused with "run trajrl verify NAME": run
`trajrl verify NAME`, then try again.

## Web, network, copies

| Task | Command |
|---|---|
| serve its web ports 443/80 publicly, or stop | `trajrl share set-public NAME --json`, `trajrl share set-private NAME --json` |
| also serve guest port PORT (3000-9999) | `trajrl share port NAME PORT --json`, `trajrl share port-rm NAME PORT --json` |
| a domain of the owner's | `trajrl domain add NAME DOMAIN --json`, `trajrl domain ls NAME --json` |
| what it may connect to | `trajrl egress NAME --json`; set with `trajrl egress NAME open\|none\|allow DEST... --json` |
| snapshots (stop NAME first) | `trajrl snapshot new NAME --json`, `trajrl snapshot ls NAME --json` |
| delete a snapshot (ask first: it is gone for good) | `trajrl snapshot rm NAME ID --json` |
| restore a snapshot (ask first: it replaces the disk) | `trajrl snapshot restore NAME ID --yes --json` |

After a snapshot restore, the next `trajrl start NAME` is refused as an older disk and prints
`trajrl start NAME -accept-older N`: that is expected, and still the human's to confirm.
