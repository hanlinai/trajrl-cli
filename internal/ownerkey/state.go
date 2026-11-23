package ownerkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// Record is what the owner's machine remembers of one sandbox. None of it is
// secret. It plays the part the key broker's record played: the boot epoch
// last confirmed (rollback detection) and the SSH host key reported at the
// first boot. Losing it loses only that history: the next unlock accepts the
// disk as it finds it (trust on first use), and the host key has to be
// learned again (sbxverify checks it against a quote).
type Record struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provisioned bool   `json:"provisioned"`
	Epoch       uint64 `json:"epoch"`
	SSHHostKey  string `json:"ssh_host_key,omitempty"`
	Policy      string `json:"policy,omitempty"`
	// FirstUse is set when this machine's record began from a disk it had
	// not seen formatted: what was accepted then was trusted on first use.
	FirstUse bool `json:"trust_on_first_use,omitempty"`
	// Image is the sandbox's own image as the owner asked for it at its
	// first boot (#38), "" for one on the platform's base image.
	// ImageDigest is what its running TD must show in RTMR3 (#112,
	// proto.RTMR3Running): the digest of Image, or proto.ImageBase. Empty
	// (a record from before #112, or one begun by trust on first use), the
	// first verification records what the TD shows (CheckImage).
	Image       string    `json:"image,omitempty"`
	ImageDigest string    `json:"image_digest,omitempty"`
	Updated     time.Time `json:"updated"`
}

// State is the owner's local, non-secret state: a JSON file next to the key
// file, and a known_hosts file the owner's SSH can use.
type State struct {
	path       string
	KnownHosts string
	mu         sync.Mutex
	doc        stateDoc
}

type stateDoc struct {
	Sandboxes map[string]*Record `json:"sandboxes"`
	// BackupChecked is when the recovery phrase was last checked against
	// the key file (sbxkey backup-check).
	BackupChecked time.Time `json:"backup_checked,omitempty"`
	// Domain is the platform's domain for sandbox names (sshpin.go).
	Domain string `json:"domain,omitempty"`
}

// OpenState reads the state file at path; a missing file is an empty state.
// knownHosts is the known_hosts file pinned host keys are written to.
//
// Several sbxkey runs may use one state at once (two sandboxes unlocked
// side by side). Every change takes a lock on path+".lock", reads the file
// again and changes only its own record, so no run loses another's.
func OpenState(path, knownHosts string) (*State, error) {
	s := &State{path: path, KnownHosts: knownHosts}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// reload reads the file into s.doc. The caller holds s.mu.
func (s *State) reload() error {
	doc := stateDoc{Sandboxes: map[string]*Record{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.doc = doc
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	if doc.Sandboxes == nil {
		doc.Sandboxes = map[string]*Record{}
	}
	for id, r := range doc.Sandboxes {
		if r == nil || r.ID != id || !proto.ValidSandboxID(id) {
			return fmt.Errorf("%s: the record of %q is not well formed", s.path, id)
		}
	}
	s.doc = doc
	return nil
}

// lock takes the state's file lock (and s.mu); the result releases both.
func (s *State) lock() (func(), error) {
	s.mu.Lock()
	f, err := os.OpenFile(s.path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		s.mu.Unlock()
		return nil, err
	}
	return func() {
		unlockFile(f)
		f.Close()
		s.mu.Unlock()
	}, nil
}

// Get returns a copy of the record of id, or nil.
func (s *State) Get(id string) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.doc.Sandboxes[id]; r != nil {
		c := *r
		return &c
	}
	return nil
}

// ByName returns a copy of the record named name, or nil.
func (s *State) ByName(name string) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.doc.Sandboxes {
		if r.Name == name {
			c := *r
			return &c
		}
	}
	return nil
}

// Records lists the records by name.
func (s *State) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	for _, r := range s.doc.Sandboxes {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ErrStateConflict is returned by Put when the record on disk has moved in
// a way this change may not undo.
var ErrStateConflict = errors.New("the record on disk conflicts with this change")

// Put stores r as the record of r.ID, under the lock and against the file as
// it is now: a boot epoch is never lowered, and a pinned SSH host key is
// never replaced unless newHostKey (the confirmed first boot of 'new'). If
// another record carries r's name, it is dropped: a name names one sandbox.
func (s *State) Put(r Record, newHostKey bool) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.reload(); err != nil {
		return err
	}
	if cur := s.doc.Sandboxes[r.ID]; cur != nil {
		if r.Epoch < cur.Epoch {
			return fmt.Errorf("%w: %s's record is at boot %d, ahead of this unlock's %d (another %s run recorded a later boot)", ErrStateConflict, cur.Name, cur.Epoch, r.Epoch, Tool)
		}
		switch {
		case cur.SSHHostKey == "" || r.SSHHostKey == cur.SSHHostKey:
		case r.SSHHostKey == "":
			r.SSHHostKey = cur.SSHHostKey
		case !newHostKey:
			return fmt.Errorf("%w: it would replace %s's pinned SSH host key", ErrStateConflict, cur.Name)
		}
		// An image digest recorded meanwhile (sbxverify's first check) is
		// kept by a change that does not set one; a first boot sets its own.
		if r.ImageDigest == "" && r.Image == "" {
			r.Image, r.ImageDigest = cur.Image, cur.ImageDigest
		}
	}
	r.Updated = time.Now().UTC().Truncate(time.Second)
	for id, o := range s.doc.Sandboxes {
		if o.Name == r.Name && id != r.ID {
			delete(s.doc.Sandboxes, id)
		}
	}
	s.doc.Sandboxes[r.ID] = &r
	return s.write()
}

// ImageCheck is the outcome of CheckImage.
type ImageCheck struct {
	// Image is the record's Image ("" for the base image) and Recorded the
	// digest it held before the check.
	Image, Recorded string
	// FirstUse: the record held no digest, and the one the TD showed is now
	// recorded (trust on first use).
	FirstUse bool
	// NoRecord: this machine has no record of the sandbox; nothing was
	// compared or recorded.
	NoRecord bool
}

// CheckImage compares image, the image a running TD of sandbox id showed
// (authenticated by RTMR3, proto.RTMR3Running), with the owner's record:
//
//   - a record with a digest (the image asked for by digest, or base) must
//     show exactly that digest;
//   - a record without one (from before #112, or begun by trust on first
//     use) records the one shown, which later checks must match.
//
// A mismatch is an error that names both. No record at all is not an error:
// the result says nothing was compared.
func (s *State) CheckImage(id, image string) (ImageCheck, error) {
	if !proto.ValidImageMeasure(image) {
		return ImageCheck{}, fmt.Errorf("the TD names its image %.80q, which is neither %q nor a sha256 digest", image, proto.ImageBase)
	}
	unlock, err := s.lock()
	if err != nil {
		return ImageCheck{}, err
	}
	defer unlock()
	if err := s.reload(); err != nil {
		return ImageCheck{}, err
	}
	r := s.doc.Sandboxes[id]
	if r == nil {
		return ImageCheck{NoRecord: true}, nil
	}
	c := ImageCheck{Image: r.Image, Recorded: r.ImageDigest}
	if r.ImageDigest != "" {
		if r.ImageDigest != image {
			asked := r.ImageDigest
			if r.Image != "" {
				asked = r.Image
			}
			return c, fmt.Errorf("REFUSED: %s runs the image %s; your record says %s (%s). It is not the image you asked for; do not use it", r.Name, image, r.ImageDigest, asked)
		}
		return c, nil
	}
	r.ImageDigest, c.FirstUse = image, true
	r.Updated = time.Now().UTC().Truncate(time.Second)
	return c, s.write()
}

// ImageDigestOf is what a first boot records as Record.ImageDigest for the
// image ref the owner asked for: its digest, proto.ImageBase for no image,
// and "" for a reference that names no digest (trust on first use).
func ImageDigestOf(ref string) string {
	if ref == "" {
		return proto.ImageBase
	}
	if r, err := proto.ParseImageRef(ref); err == nil {
		return r.Digest
	}
	return ""
}

// Rename moves the record named old to the name name, after the platform
// renamed the sandbox (#72): the unlock refuses a sandbox whose name at the
// platform is not the record's. Only the name changes: the ID, and with it
// the disk secret (DiskSecret derives it from the ID), the boot epoch and
// the pinned SSH host key stay. A record already named name is not
// replaced.
func (s *State) Rename(old, name string) (*Record, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.reload(); err != nil {
		return nil, err
	}
	var r *Record
	for _, x := range s.doc.Sandboxes {
		switch x.Name {
		case name:
			return nil, fmt.Errorf("your record has a sandbox called %s already (%s); remove that record first if the platform has no such sandbox any more", name, x.ID)
		case old:
			r = x
		}
	}
	if r == nil {
		return nil, fmt.Errorf("your record has no sandbox called %s", old)
	}
	r.Name = name
	r.Updated = time.Now().UTC().Truncate(time.Second)
	if err := s.write(); err != nil {
		return nil, err
	}
	c := *r
	return &c, nil
}

// MoveHostKey pins key for hosts in the known_hosts file, as PinHostKey
// does, and drops the line it had for exactly the hosts from (a sandbox's
// old name, after a rename). Lines for other host lists are left as they
// are.
func (s *State) MoveHostKey(from, hosts []string, key string) (string, error) {
	old, err := KnownHostsLine(from, key)
	if err != nil {
		return "", err
	}
	line, err := s.PinHostKey(hosts, key)
	if err != nil {
		return "", err
	}
	unlock, err := s.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	return line, s.dropKnownHosts(strings.Fields(old)[0])
}

// dropKnownHosts removes the known_hosts lines whose host field is field.
// The caller holds the lock.
func (s *State) dropKnownHosts(field string) error {
	b, err := os.ReadFile(s.KnownHosts)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] != field {
			out = append(out, l)
		}
	}
	return writeAtomic(s.KnownHosts, []byte(strings.Join(out, "\n")+"\n"), 0o644)
}

// BackupChecked is when the recovery phrase was last checked.
func (s *State) BackupChecked() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.BackupChecked
}

// MarkBackupChecked records a successful backup check.
func (s *State) MarkBackupChecked() error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.reload(); err != nil {
		return err
	}
	s.doc.BackupChecked = time.Now().UTC().Truncate(time.Second)
	return s.write()
}

func (s *State) write() error {
	b, err := json.MarshalIndent(s.doc, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path, append(b, '\n'), 0o600)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// KnownHostsLine is the known_hosts line pinning key for hosts.
func KnownHostsLine(hosts []string, key string) (string, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return "", errors.New("not an SSH public key")
	}
	return knownhosts.Line(hosts, pk), nil
}

// PinHostKey writes the line for hosts into the known_hosts file, replacing
// any line it had for exactly the same hosts.
func (s *State) PinHostKey(hosts []string, key string) (string, error) {
	line, err := KnownHostsLine(hosts, key)
	if err != nil {
		return "", err
	}
	field := strings.Fields(line)[0]
	unlock, err := s.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	old, err := os.ReadFile(s.KnownHosts)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var out []string
	for _, l := range strings.Split(string(old), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] != field {
			out = append(out, l)
		}
	}
	out = append(out, line)
	return line, writeAtomic(s.KnownHosts, []byte(strings.Join(out, "\n")+"\n"), 0o644)
}
