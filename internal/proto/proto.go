// Package proto is the wire contract between the in-guest boot agent and the
// party that holds the sandbox's disk secret: the sandbox owner's own tool
// (internal/ownerkey), or the key broker of the earlier design. Transport is
// TLS 1.3, the guest being the client; messages are newline-delimited JSON on
// that one connection. The guest pins no server certificate: the quote binds
// the session through the TLS exporter (ReportData), and the verifier checks
// that binding against its own session.
package proto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"regexp"
)

const (
	// Version 2 adds the boot epoch (rollback detection): the release
	// carries the broker's recorded epoch, and after unlocking the guest
	// answers with TypeEpoch or TypeRollback. Version 1 is still accepted for
	// a sandbox that has never confirmed an epoch.
	Version    = 2
	MinVersion = 1

	// TLS exporter label (RFC 5705 / RFC 8446 §7.5) used to bind a quote to
	// the TLS session that will carry the key.
	ExporterLabel = "EXPORTER-tdx-sandbox-kbs-v1"
	ExporterLen   = 32
	NonceLen      = 32
	SecretLen     = 32

	ModeTDX = "tdx"
	// ModeDev is the development-only path with no attestation at all. It is
	// refused unless both broker and sandbox are explicitly marked insecure.
	ModeDev = "dev-insecure"

	TypeHello       = "hello"
	TypeChallenge   = "challenge"
	TypeEvidence    = "evidence"
	TypeRelease     = "release"
	TypeProvisioned = "provisioned"
	TypeAck         = "ack"
	TypeEpoch       = "epoch"
	TypeRollback    = "rollback"
	// TypeBlankDisk: the release said the sandbox is provisioned and its
	// disk is blank; the guest did not format it and stops.
	TypeBlankDisk = "blank-disk"
	TypeError     = "error"
)

// Msg is every message on the wire; unused fields are omitted.
type Msg struct {
	Type    string `json:"type"`
	Version int    `json:"version,omitempty"`

	SandboxID string `json:"sandbox_id,omitempty"` // hello
	Nonce     []byte `json:"nonce,omitempty"`      // challenge
	Mode      string `json:"mode,omitempty"`       // evidence, release
	Quote     []byte `json:"quote,omitempty"`      // evidence

	DiskSecret     []byte `json:"disk_secret,omitempty"`     // release
	Provisioned    bool   `json:"provisioned,omitempty"`     // release
	AuthorizedKeys string `json:"authorized_keys,omitempty"` // release
	// SetupScript is run once in the sandbox after its first boot. Sent
	// with the release that tells the guest to format, and never again.
	SetupScript string `json:"setup_script,omitempty"` // release
	// Image is the sandbox's image (#38), REGISTRY/REPO@sha256:..., by
	// digest only (ParseImageRef); RegistryAuth the credential for its
	// registry, "USER:PASSWORD", or empty. Like the setup script, both come
	// only from the owner's tool, with the release that tells the guest to
	// format, and never again; the guest pulls the image at that first boot,
	// verifies it against the digest and unpacks it onto the encrypted disk.
	// Neither is ever stored outside the TD by the guest.
	Image        string `json:"image,omitempty"`         // release
	RegistryAuth string `json:"registry_auth,omitempty"` // release

	SSHHostPubKey string `json:"ssh_host_pubkey,omitempty"` // provisioned

	// Epoch: in a release, the boot epoch the broker recorded; in
	// provisioned, epoch and rollback, the one on the guest's disk.
	// EpochOverride (release): the owner accepted whatever the disk holds,
	// once (a deliberate restore).
	Epoch         uint64 `json:"epoch,omitempty"`
	EpochOverride bool   `json:"epoch_override,omitempty"`
	// AcceptEpoch (release; owner's tool): a disk at another epoch than the
	// record's is accepted if, and only if, it is at exactly this one, older
	// (a snapshot the owner restored) or newer (booted from another machine
	// of the owner's). 0: none.
	AcceptEpoch uint64 `json:"accept_epoch,omitempty"`
	// BindRTMR3 (release; owner's tool): the guest closes its attestation
	// window with RTMR3OwnerUnlock of the disk secret instead of the fixed
	// RTMR3BootDone, so that a quote of the running sandbox shows whose
	// secret unlocked it.
	BindRTMR3 bool `json:"bind_rtmr3,omitempty"`
	// WebNames (release; owner's tool, #113): the sandbox's names at the
	// platform's web router, the only ones its web server asks
	// certificates for (CheckWebNames). Sent with every release, so that a
	// rename or a domain added takes effect at the next start; the guest
	// replaces what the disk held with them. Required (#118, image
	// revision 17 on): a release without the field (nil: an owner's tool
	// older than WebNamesTool) is refused by the guest before the disk is
	// touched; an empty list ([]) is sent as such and means no certificate
	// for any name. omitzero keeps the two apart on the wire: nil is left
	// out, an empty slice is "web_names":[].
	WebNames []string `json:"web_names,omitzero"`
	// KeyStatement (release; owner's tool, #65): the account's latest
	// owner-signed statement of its SSH keys (internal/keystmt), as the
	// platform relays it, at every unlock. The guest does not trust it for
	// coming in the release: it is applied in the sandbox only if a key the
	// sandbox already trusts signed it, with a seq above the last applied.
	// At most MaxKeyStatement bytes. Empty: the sandbox's keys stay as
	// they are.
	KeyStatement string `json:"key_statement,omitempty"`

	Error string `json:"error,omitempty"`
}

var sandboxIDRe = regexp.MustCompile(`^sbx-[0-9a-f]{16}$`)

// ValidSandboxID reports whether s is a well-formed sandbox ID. The form fits
// the 20-byte virtio-blk serial that carries it into the guest.
func ValidSandboxID(s string) bool { return sandboxIDRe.MatchString(s) }

func lp(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	h.Write(n[:])
	h.Write(b)
}

// ReportData is the 64-byte TDX REPORTDATA both sides compute. It commits the
// quote to one sandbox, one verifier challenge and one TLS session.
func ReportData(sandboxID string, nonce, exporter []byte) [64]byte {
	h := sha512.New()
	lp(h, []byte("tdx-sandbox-kbs/v1/report-data"))
	lp(h, []byte(sandboxID))
	lp(h, nonce)
	lp(h, exporter)
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MRConfigID is the value a VMM that supports it places in the TD's
// MRCONFIGID so the sandbox identity is fixed at TD creation.
func MRConfigID(sandboxID string) [48]byte {
	h := sha512.New384()
	lp(h, []byte("tdx-sandbox-kbs/v1/mrconfigid"))
	lp(h, []byte(sandboxID))
	var out [48]byte
	copy(out[:], h.Sum(nil))
	return out
}

// DiskKeys are derived inside the guest from the released secret.
type DiskKeys struct {
	Crypt     []byte // 64 bytes, aes-xts-plain64
	Integrity []byte // 32 bytes, dm-integrity hmac-sha256 over data
	Journal   []byte // 32 bytes, dm-integrity hmac-sha256 over journal + superblock
}

// DeriveDiskKeys derives the keys with no salt: the derivation of a disk of
// the earlier format, which carries none.
func DeriveDiskKeys(secret []byte) (DiskKeys, error) { return DeriveDiskKeysSalted(secret, nil) }

// DiskSaltLen is the length of the random salt a disk is formatted with. It
// is kept, in the clear, in the disk's header (image/initrd/sandbox-storage).
const DiskSaltLen = 32

// DeriveDiskKeysSalted derives the keys of one disk format from the secret
// and that format's salt. A secret is the same at every format of a sandbox
// (it comes from the owner's master key and the sandbox's ID), so without the
// salt two formats of one sandbox would have the same keys: the same XTS
// keystream at the same sector, and sectors of the earlier format carrying
// tags valid in the later one. The salt is not secret; changing it on the
// disk only yields keys that do not open it.
func DeriveDiskKeysSalted(secret, salt []byte) (DiskKeys, error) {
	d := func(info string, n int) ([]byte, error) {
		return hkdf.Key(sha256.New, secret, salt, "tdx-sandbox/v1/"+info, n)
	}
	var k DiskKeys
	var err error
	if k.Crypt, err = d("dm-crypt aes-xts-plain64", 64); err != nil {
		return k, err
	}
	if k.Integrity, err = d("dm-integrity hmac-sha256", 32); err != nil {
		return k, err
	}
	k.Journal, err = d("dm-integrity journal hmac-sha256", 32)
	return k, err
}

// RTMR3BootDone is extended into RTMR3 by the boot agent once key exchange is
// over and before any mutable userspace runs. The broker only releases keys
// while RTMR3 is still zero, so code running after the trusted boot stage
// cannot obtain an acceptable quote.
func RTMR3BootDone() [48]byte {
	return sha512.Sum384([]byte("tdx-sandbox/v1/boot-stage-complete"))
}

// RTMR3AfterBoot is the value RTMR3 has once the boot agent of a sandbox the
// broker unlocked has closed the attestation window: the register starts at
// zero and the agent extends it with RTMR3BootDone. A running sandbox shows
// one extension more, its image's: RTMR3Running(RTMR3BootDone(), image).
func RTMR3AfterBoot() [48]byte { return RTMR3After(RTMR3BootDone()) }

// RTMR3After is RTMR3 after the first extension, with v, that a boot makes
// (the unlock): the register starts at zero.
func RTMR3After(v [48]byte) [48]byte { return RTMR3Extend([48]byte{}, v) }

// RTMR3Extend is what extending a register that holds prev with v leaves in
// it: SHA-384(prev || v).
func RTMR3Extend(prev, v [48]byte) [48]byte {
	return sha512.Sum384(append(prev[:], v[:]...))
}

// ImageBase is what a sandbox on the platform's base image, without an
// image of its owner's, extends RTMR3 with in place of a digest (#112), so
// that every sandbox's RTMR3 has the same two extensions.
const ImageBase = "base"

// ValidImageMeasure reports whether s is what the image extension takes:
// ImageBase or an image digest ("sha256:" and 64 lower-case hex digits).
func ValidImageMeasure(s string) bool { return s == ImageBase || ValidDigest(s) }

// RTMR3Image is the second extension of RTMR3, made at every boot once the
// initrd knows which image the root is (#112): the owner's image's digest,
// read from the sandbox's encrypted disk (image.digest), or ImageBase.
// SHA-384("tdx-sandbox image v1\x00" || image).
func RTMR3Image(image string) [48]byte {
	return sha512.Sum384(append([]byte("tdx-sandbox image v1\x00"), image...))
}

// RTMR3Running is the value RTMR3 has in a running sandbox: unlock is what
// the boot agent extended it with when the disk secret arrived
// (RTMR3BootDone, or RTMR3OwnerUnlock of the owner's secret), then the
// image's extension (RTMR3Image). A quote showing it comes from a TD that
// was unlocked so and whose root is that image: the image a running TD
// reports for itself is authentic exactly when this equality holds.
//
// The quote taken during the unlock shows neither: RTMR3 is zero then.
func RTMR3Running(unlock [48]byte, image string) [48]byte {
	return RTMR3Extend(RTMR3After(unlock), RTMR3Image(image))
}

// RTMR3OwnerUnlock is what the boot agent extends RTMR3 with when the
// owner's tool unlocked it (BindRTMR3): a one-way commitment to the disk
// secret. The owner, who can derive the secret, can compute it; nobody who
// cannot derive the secret can make a TD show it. A sandbox the host booted
// and unlocked with a secret of its own shows another value.
func RTMR3OwnerUnlock(diskSecret []byte) ([48]byte, error) {
	var out [48]byte
	if len(diskSecret) != SecretLen {
		return out, errors.New("a disk secret is 32 bytes")
	}
	b, err := hkdf.Key(sha256.New, diskSecret, nil, "tdx-sandbox/rtmr3-owner/v1", 48)
	copy(out[:], b)
	return out, err
}

// UserReportData is the REPORTDATA of a quote a sandbox's owner asks their
// running sandbox for, to check for themselves what they are talking to. It
// commits the quote to a nonce of the owner's choosing (so it is fresh) and
// to the SSH host key of the sandbox (so the SSH session the owner is in ends
// inside the TD that produced the quote). hostKey is the key as "type base64".
//
// The label differs from ReportData's, so such a quote can never stand in
// for the evidence of a boot.
func UserReportData(nonce []byte, hostKey string) [64]byte {
	h := sha512.New()
	lp(h, []byte("tdx-sandbox/v1/owner-attestation"))
	lp(h, nonce)
	lp(h, []byte(hostKey))
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MaxSetupScript bounds a first-boot setup script.
const MaxSetupScript = 10 << 10

// MaxKeyStatement bounds a signed statement of keys in a release (#65), so
// that a first boot's release, with its setup script, stays within the
// guest's 64 KiB line.
const MaxKeyStatement = 24 << 10
