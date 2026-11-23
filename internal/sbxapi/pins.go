package sbxapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Pin is sbxverify's record of a sandbox it verified: the SSH host key the
// TD's quote carried. It is what the API client trusts the server by.
type Pin struct {
	Name     string    `json:"name,omitempty"`
	ID       string    `json:"id"`
	HostKey  string    `json:"ssh_host_key"`
	HTTPSURL string    `json:"https_url,omitempty"`
	Entry    string    `json:"entry,omitempty"`
	Verified time.Time `json:"verified"`
}

// Host is the pin's TLS server name at the web router (from its HTTPS URL).
func (p Pin) Host() string {
	if u, err := url.Parse(p.HTTPSURL); err == nil {
		return u.Hostname()
	}
	return ""
}

// Pins is the file of pins, keyed by the sandbox's name (or its ID when it
// was verified by address).
type Pins struct {
	Sandboxes map[string]Pin `json:"sandboxes"`
}

// DefaultPinFile is ~/.config/sbx/verified.json (or under $XDG_CONFIG_HOME).
func DefaultPinFile() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "sbx", "verified.json")
}

// LoadPins reads the file; a missing file is an empty one.
func LoadPins(path string) (*Pins, error) {
	p := &Pins{Sandboxes: map[string]Pin{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.Sandboxes == nil {
		p.Sandboxes = map[string]Pin{}
	}
	return p, nil
}

// RecordPin adds or replaces the pin of a sandbox sbxverify has just
// verified. The file is replaced whole, mode 0600.
func RecordPin(path string, pin Pin) error {
	if _, err := ParsePin(pin.HostKey); err != nil {
		return err
	}
	ps, err := LoadPins(path)
	if err != nil {
		return err
	}
	key := pin.Name
	if key == "" {
		key = pin.ID
	}
	// One pin per sandbox: a sandbox verified under a new name (renamed,
	// #72) drops the pin of its old one, whose host name no longer
	// reaches it.
	for k, p := range ps.Sandboxes {
		if k != key && pin.ID != "" && p.ID == pin.ID {
			delete(ps.Sandboxes, k)
		}
	}
	ps.Sandboxes[key] = pin
	b, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".verified-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Lookup finds the pin for what the user named: a sandbox's name or ID as
// sbxverify recorded it, or its host name at the web router.
func (ps *Pins) Lookup(name string) (Pin, error) {
	if p, ok := ps.Sandboxes[name]; ok {
		return p, nil
	}
	var found []Pin
	for _, p := range ps.Sandboxes {
		if p.ID == name || (strings.Contains(name, ".") && strings.EqualFold(p.Host(), name)) {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return Pin{}, fmt.Errorf("no record of %s: run sbxverify for it first (it records the host key the TD vouches for), or give the key with --pin", name)
	}
	return Pin{}, fmt.Errorf("%d records match %s: name it by its sandbox name or give --pin", len(found), name)
}
