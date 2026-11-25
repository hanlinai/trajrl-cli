#!/bin/bash
# Builds the owner's command line, trajrl (#123), for release, reproducibly (#63):
#
#   release/build-owner-tools.sh SRCDIR OUTDIR
#
# SRCDIR is a tree with cmd/trajrl: the exported module
# (release/export-owner-tools.sh), the public repository, or this repository itself.
# OUTDIR gets six binaries, trajrl-OS-ARCH for linux and darwin on amd64 and
# arm64, and trajrl-windows-amd64.exe and trajrl-windows-arm64.exe, and
# SHA256SUMS. Two runs on the same source give the same bytes, on any machine
# with Docker.
#
# These are the names the installers fetch from their TRAJRL_BASE_URL
# (public/trajrl/install.sh: trajrl-OS-ARCH; public/trajrl/install.ps1:
# trajrl-windows-ARCH.exe), with SHA256SUMS beside them: publish OUTDIR as it
# is under that URL (release hosting: #63).
#
# How: inside the pinned Go image (GO_IMAGE, by digest), CGO_ENABLED=0,
# -trimpath, -buildvcs=false, -ldflags='-s -w -buildid='. No build tags: the
# rehearsal tag (#107) adds sbxkey -dev-insecure-rehearsal, which hands a TD
# its disk secret without attestation, and the tag tcbexception (#82) adds
# the validation-only TCB exception, which accepts an out-of-date TDX module;
# a release never has either, and this script refuses binaries that do. (The
# old sbxkey, sbxverify and sbxapi are inside trajrl: trajrl sbxkey ...)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
SRC=$(readlink -f "${1:?usage: release/build-owner-tools.sh SRCDIR OUTDIR}")
OUT=${2:?usage: release/build-owner-tools.sh SRCDIR OUTDIR}
die() { echo "build-owner-tools: $*" >&2; exit 1; }

# The pinned toolchain: release/versions.env in the public tree, the image
# pins in this repository.
if [ -z "${GO_IMAGE:-}" ]; then
	if [ -f "$here/versions.env" ]; then . "$here/versions.env"; else . "$here/../image/versions.env"; fi
fi
[[ $GO_IMAGE == *@sha256:* ]] || die "GO_IMAGE must name an image by digest, not $GO_IMAGE"
[ -d "$SRC/cmd/trajrl" ] || die "$SRC has no cmd/trajrl"
[ ! -e "$OUT" ] || [ -z "$(ls -A "$OUT")" ] || die "$OUT is not empty"
mkdir -p "$OUT"; OUT=$(readlink -f "$OUT")

TOOL=trajrl
TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
# bin OS/ARCH: the file name of the binary for that target.
bin() { local n="$TOOL-${1%/*}-${1#*/}"; [ "${1%/*}" != windows ] || n="$n.exe"; echo "$n"; }

docker run --rm --user "$(id -u):$(id -g)" -v "$SRC":/src:ro -v "$OUT":/o -w /src \
	-e HOME=/tmp -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local \
	-e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod -e GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" \
	-e TOOL="$TOOL" -e TARGETS="$TARGETS" "$GO_IMAGE" sh -euc '
		go version
		for t in $TARGETS; do
			os=${t%/*} arch=${t#*/} ext=
			[ "$os" != windows ] || ext=.exe
			GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w -buildid=" -o /o/$TOOL-$os-$arch$ext ./cmd/$TOOL
		done
		# The build settings each binary records: no -tags, the flags above.
		for b in /o/$TOOL-*; do
			if go version -m "$b" | grep -E "^\s+build\s+-tags="; then echo "$b was built with a build tag" >&2; exit 1; fi
		done
		go version -m /o/$TOOL-linux-amd64 | grep -E "^\s+(path|mod|build)\s"
	' 2>&1 | grep -v '^go: downloading'
[ "${PIPESTATUS[0]}" = 0 ] || die "the build failed"

n=0
for t in $TARGETS; do
	b="$OUT/$(bin "$t")"
	[ -s "$b" ] || die "$b was not built"
	# Not one of the strings only the rehearsal build holds
	# (cmd/trajrl/buildtag_test.go), in any binary.
	for s in dev-insecure-rehearsal AllowUnattestedRehearsal unattestedRehearsal "NOT FOR ANY REAL USE"; do
		! grep -qaF -- "$s" "$b" || die "$b holds \"$s\": a rehearsal build is never released"
	done
	# Nor one of those only the validation build of the TCB exception holds
	# (cmd/kbs/tcbexception_test.go).
	for s in LoadTCBException experimental-tcb-exception "EXPERIMENTAL: TDX module TCB"; do
		! grep -qaF -- "$s" "$b" || die "$b holds \"$s\": a build with a TCB exception is never released"
	done
	n=$((n + 1))
done
[ "$(ls "$OUT" | wc -l)" = "$n" ] || die "$OUT holds other files than the $n binaries: $(ls "$OUT" | tr '\n' ' ')"
(cd "$OUT" && LC_ALL=C sha256sum "$TOOL"-* | LC_ALL=C sort -k2 >SHA256SUMS)
echo "built $n binaries in $OUT; none was built with a tag or holds -dev-insecure-rehearsal or a TCB exception"
cat "$OUT/SHA256SUMS"
