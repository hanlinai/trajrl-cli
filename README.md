# trajrl

> This repository is generated from the TrajRL monorepo. Open issues here; changes are made
> upstream and arrive in the next sync, so pull requests here are not merged as they are.

`trajrl` is the command line a TrajRL sandbox's owner runs on their own machine (Linux, macOS,
Windows):

- `trajrl verify NAME` checks a running sandbox: that it is a genuine Intel TDX guest on a
  platform Intel rates current, that it booted the image you expect, and that your SSH session
  ends inside it.
- `trajrl new`, `start` and `unlock` hold your disk key, verify the TD and unlock it at
  every start.
- `trajrl ssh`, `exec` and `cp` reach a sandbox only with the host key verified here.
- Every other command is the platform's entry point's, forwarded as it is.
- `trajrl skills install` gives coding agents the skills in `skills/`.
- Python SDK: `pip install trajrl-sdk` (`import trajrl`) drives this `trajrl` from Python
  through its `--json` interface; see [`sdk/python`](sdk/python).

None of it trusts the service that runs the sandbox. This repository holds its full source; the
released binaries are built from it and rebuild bit for bit (see [Build from source](#build-from-source)).

## Install

**Status:** the licence is not chosen yet (#130).

Homebrew (macOS, Linux): this repository is the tap.

```
brew tap hanlinai/trajrl-cli https://github.com/hanlinai/trajrl-cli
brew install trajrl
```

Scoop (Windows): this repository is the bucket.

```
scoop bucket add trajrl https://github.com/hanlinai/trajrl-cli
scoop install trajrl
```

Debian, Ubuntu (`.deb`) and Fedora, RHEL (`.rpm`): download the package for your machine from
[Releases](https://github.com/hanlinai/trajrl-cli/releases), then

```
sudo dpkg -i trajrl_VERSION_linux_amd64.deb
sudo rpm -i trajrl_VERSION_linux_amd64.rpm
```

Install scripts (download the binary for your machine, check it against `SHA256SUMS`, install it):

```
curl -fsSL https://sandbox.trajrl.com/trajrl/install.sh | sh             # Linux, macOS
irm https://sandbox.trajrl.com/trajrl/install.ps1 | iex                  # Windows PowerShell
```

Go (builds from source):

```
go install github.com/hanlinai/trajrl-cli/cmd/trajrl@latest
```

## Verify a download

Every release carries `SHA256SUMS`, over the raw binaries (`trajrl-linux-amd64`,
`trajrl-linux-arm64`, `trajrl-darwin-amd64`, `trajrl-darwin-arm64`, `trajrl-windows-amd64.exe`,
`trajrl-windows-arm64.exe`), the archives and the packages. Check what you downloaded:

```
sha256sum -c --ignore-missing SHA256SUMS                                  # Linux
shasum -a 256 -c --ignore-missing SHA256SUMS                              # macOS
(Get-FileHash trajrl-windows-amd64.exe -Algorithm SHA256).Hash            # Windows: compare with SHA256SUMS
```

`SHA256SUMS` from the same page as the binary only shows that the download is intact; there is
no release signature yet (#130). That the binary is this source is shown by building it
yourself.

## Build from source

With Docker, in this tree:

```
release/build-owner-tools.sh . out
```

It builds the six binaries inside the Go image pinned by digest in `release/versions.env`, with
`CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, `-ldflags='-s -w -buildid='` and no build tags,
and writes `out/SHA256SUMS`: the same bytes as the release's raw binaries. GoReleaser
(`.goreleaser.yaml`) builds the releases with the same settings and the same Go, and CI checks
that the two agree.

## What it does

```
trajrl verify web -policy image.json      # the entry point and its key from trajrl setup
trajrl verify web -entry entry.example:2222 -entry-key 'ssh-ed25519 AAAA…' -policy image.json
```

1. It asks the entry point which sandbox `web` is (its ID), and connects to it by name. The entry
   point carries the connection; the SSH session is with the sandbox.
2. It accepts whatever SSH host key answers and **remembers it**. No list of known hosts is
   consulted.
3. It makes up a 32-byte nonce and runs `sandbox-attest <nonce>` in the sandbox. That program
   asks the CPU for a TDX quote whose report data is a hash of the nonce and of the sandbox's SSH
   host key, and prints it. It cannot make a quote itself; a tampered copy can refuse, not lie.
4. It verifies the quote with the same verifier the key broker uses, in its strictest form: no
   exception of any kind exists in this tool.

| It checks | Which shows |
|---|---|
| The quote's signature chain up to Intel's root, and Intel's revocation lists | A genuine Intel quoting enclave signed it |
| Intel's current rating of the platform, the quoting enclave and the TDX module: all `UpToDate` | The machine has no known unpatched weakness in what TDX rests on |
| `MRTD`, `RTMR0`–`RTMR2`, attributes and `XFAM` against the policy file; not a debug TD | It booted the firmware, kernel, initrd and command line the owner expects, and its memory is not readable by the host |
| `RTMR3` is exactly the value of its two extensions (below): the unlock, then the image its root is made of | It went through the measured boot stage, and that stage is over; its root is the image it names (the owner's image's digest, or `base`) |
| `MRCONFIGID` is the sandbox's ID | The TD was launched as this sandbox and no other |
| The report data carries the nonce | The quote was made now, for this question |
| The report data carries the host key **the SSH session was authenticated with** | The session ends inside the TD that signed the quote. Something in between that answers SSH itself and relays the question brings back a quote for another key, and is caught |

If all of it holds it prints `VERIFIED` and what it found; otherwise `NOT VERIFIED`, the step that
failed, and exit status 1. Under a `NOT VERIFIED` that comes from the quote it can also list the
checks one by one, which hold and which do not; the verdict stands whatever the list shows.

By hand, the same thing is `ssh root@sandbox sandbox-attest $(openssl rand -hex 32)` and any TDX
quote verifier, with the report data computed as `internal/proto` `UserReportData` does.

### RTMR3: two extensions

`RTMR3` is zero when the disk secret is released, and the initrd extends it twice before the
root is mounted ([`trusted-boot.md`](https://github.com/hanlinai/engy-trajrl-web/blob/console/prototype/docs/trusted-boot.md), #112):

1. **The unlock.** When the secret arrives: `proto.RTMR3OwnerUnlock(secret)`, a commitment to the
   disk secret, if the owner's `trajrl` unlocked it; `proto.RTMR3BootDone()`, a fixed string, if
   the key broker did.
2. **The image.** At every boot, `sandbox-storage mount-root` runs `sandbox-agent extend-image`
   with `proto.RTMR3Image(IMAGE)` = SHA-384(`"tdx-sandbox image v1\0"` ‖ IMAGE). IMAGE is the
   owner's image's digest, read from the encrypted disk's `image.digest`, or `base` for a sandbox
   on the base image. A failed extension stops the boot with nothing mounted.

A running sandbox therefore shows `proto.RTMR3Running(unlock, IMAGE)`. `sandbox-attest` prints the
image the sandbox names (an older one does not; `trajrl verify` then reads `/run/tdx-sandbox/image` in
the same session), and `trajrl verify` requires `RTMR3` to be exactly the value for that image, which
makes the name authentic. Anything that is neither `base` nor a `sha256:` digest is refused. With
`-owner-key` it then compares the image with the owner's record (`sandboxes.json`, written by
`trajrl new`, `start` and `unlock`): a recorded digest must match exactly; a record from before #112, with no digest,
records this one on the first check (trust on first use) and later checks must find the same; a
mismatch is refused, naming both. A sandbox booted from an image older than revision 16 shows one
extension only and is refused. The unlock's own quote is taken before either extension, so the
unlock protocol is unchanged. The two-extension value has not yet been seen on hardware (#79);
under emulation the scenario's step `image` and `tests/oci-rehearsal.sh` step 2b compare the
image with the record without any quote (a `-tags rehearsal` build, never `VERIFIED`).

## Every line of the output

`trajrl verify` prints one of two verdicts, `VERIFIED` (exit status 0) or `NOT VERIFIED` (exit status
1). Only the first line decides; everything under it explains.

**`VERIFIED`**, line by line:

| Line | What it means |
|---|---|
| `VERIFIED: sbx-… is a genuine Intel TDX guest running the image you expect.` | Every check below held. Nothing was skipped: the tool has no option to skip one. |
| `quote` | The quote's signature chains to Intel's root certificate (built into the tool), and Intel's revocation lists, fetched now, revoke nothing in that chain. |
| `platform … (TDX module …, quoting enclave …)` | Intel's rating of the platform, the TDX module and the quoting enclave, fetched now. All three are `UpToDate`, or the verdict would be `NOT VERIFIED`. |
| `image … MRTD … RTMR1 …` | The quote's measurements equal one of your `-policy` files, named here: `MRTD` the firmware, `RTMR1` the kernel, initrd and command line (with the root filesystem's hash). `RTMR0`, `RTMR2`, the attributes and `XFAM` were compared too. |
| `boot` | `RTMR3` is that of a completed measured boot stage (both extensions, for the image the sandbox names), and the TD's debug bit is off: the host cannot read its memory. |
| `root` | The image the sandbox's root is made of, which `RTMR3`'s second extension shows: `the platform's base image, no image of the owner's`, or `the owner's image sha256:… over the base image`. |
| `your image` (with `-owner-key`) | That image held against your record: the image you created it with, the base image as your record says, a digest now recorded for the first time (trust on first use), or no record of this sandbox to compare with. A mismatch is a `NOT VERIFIED` naming both digests. |
| `identity` | `MRCONFIGID` is this sandbox's ID: the TD was launched as this sandbox and no other. |
| `fresh` | The quote's report data carries the 32-byte nonce chosen on your machine for this run (its first 16 hex digits shown): the quote was made now. |
| `this session` | The report data also carries the SSH host key that authenticated this session: your session ends inside the TD that made the quote. |
| `your key` (with `-owner-key`) | `RTMR3`'s first extension shows the disk secret your key file (`trajrl key init`) gives this sandbox: you unlocked it, nobody else. |
| `note: the service lists another host key` | The service's list disagrees with the TD. The TD's key is the one checked; the service's is wrong or stale. |
| `Check by check:` `[ok  ] …` | The same quote seen check by check (the table in "What it does"). It explains the verdict; it is not a second verdict. |
| `recorded … in FILE` | The verified host key is saved for `trajrl exec` and `trajrl cp`, which then talk to the sandbox's API only over that key (#106). `-record ""` saves nothing. |
| `What this does not tell you: …` | Printed every time: who else can obtain the disk key (left out when you unlocked it yourself), and whether the image deserves your trust. |

**`NOT VERIFIED`**, line by line (on stderr):

| Line | What it means |
|---|---|
| `NOT VERIFIED: REASON` | The first step that failed. Before a quote: no entry point key, no SSH key, the sandbox not running, the login refused, no quote printed. On the quote: the failing check, e.g. a TCB rating, a measurement, the nonce or the host key. |
| `Intel's rating: platform …, TDX module …, quoting enclave …` | Shown when the quote got as far as Intel's rating. Anything but `UpToDate` on any of the three is enough to refuse. |
| `Check by check:` `[ok  ]` / `[FAIL] … : DETAIL` | Which checks held and which did not, for the reader. A list with one `FAIL` and the rest `ok` is still `NOT VERIFIED`. |
| `The verdict above stands: …` | There is no option to overlook a failing check. |
| `(No check-by-check account: …)` | A second look at the quote disagreed with the verdict (for example, Intel's collateral changed between the two). The list is left out; the verdict stands. |

**What `NOT VERIFIED` means.** The tool could not establish what `VERIFIED` states. It does not say
the sandbox is compromised: an out-of-date platform rating, a policy file for another image
revision, or a network failure all end here. It does say that nothing about the sandbox is
proven: do not give it secrets until a run says `VERIFIED`. The reason line tells which case it
is; a refusal over the host key ("something between you and the sandbox is answering in its
place"), over `-owner-key` ("this sandbox was not unlocked with your key, or its root is not the
image it names") or over the image against your record (both digests named) is the one to report
at once.

**With `-json`** the same verdict is one JSON object on stdout, and the lines above go to stderr:
`verdict` (`VERIFIED` or `NOT VERIFIED`), `reason` (on refusal), `sandbox_id`, `checked_at`,
`quote` (the verifier's facts, `null` if no quote was reached), `unlocked_by_owner` and `image`
(the image the sandbox names, a digest or `base`). The exit
status is the same.

## What it does not show

- **Who else can obtain the sandbox's disk key.** The key broker holds it, and the broker runs on
  an ordinary machine of the service's
  ([issue #22](https://github.com/hanlinai/engy-trajrl-web/issues/22)). A verified sandbox is one
  nobody can look into while it runs; its disk at rest is as private as the broker is.
- That the disk has not been rolled back to an older state ([`threat-model.md`](https://github.com/hanlinai/engy-trajrl-web/blob/console/prototype/docs/threat-model.md)).
- Anything about what the owner, as root, has installed since.
- Anything about a sandbox that is not running.

