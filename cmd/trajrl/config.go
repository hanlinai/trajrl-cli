package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// config is trajrl's configuration, <dir>/config.json (mode 0600), written
// by setup. The owner's other data stays where the old tools keep it, in
// its formats: the key file and the record of sandboxes in sbxkey's
// directory ($SBXKEY_DIR), sbxverify's record (~/.config/sbx/verified.json),
// and ~/.ssh/sbx_known_hosts.
type config struct {
	// Entry is the entry point, HOST:PORT; EntryKey its SSH host key as
	// the platform publishes it, pinned.
	Entry    string `json:"entry"`
	EntryKey string `json:"entry_key"`
	// Identity is your SSH private key file ("": your SSH agent, or the
	// first of ~/.ssh/id_ed25519, id_ecdsa, id_rsa without a passphrase:
	// identityFile). setup saves the one it found.
	Identity string `json:"identity,omitempty"`
	// Domain is the platform's domain for sandbox names, NAME.DOMAIN.
	Domain string `json:"domain,omitempty"`
	// EntryName, from an older setup only, is the name it pinned the
	// entry point's key under in your ssh's known_hosts, for its ProxyJump
	// lines; setup, run again, takes that pin out. SSHConfig is the lines
	// installed in your ssh's config, in SSHDir ("": ~/.ssh). setup
	// --remove takes them out.
	EntryName string `json:"entry_name,omitempty"`
	SSHConfig string `json:"ssh_config,omitempty"`
	SSHDir    string `json:"ssh_dir,omitempty"`
}

// dir is trajrl's own directory: $TRAJRL_DIR, or trajrl in the user's
// configuration directory.
func dir() string {
	if d := os.Getenv("TRAJRL_DIR"); d != "" {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "trajrl")
	}
	return ".trajrl"
}

func configPath() string { return filepath.Join(dir(), "config.json") }

// sshDirOf is the SSH directory sshDir names, "" for ~/.ssh.
func sshDirOf(sshDir string) string {
	if sshDir != "" {
		return sshDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}

// identityFile is the SSH key file trajrl logs in with, as ssh would pick
// one: the configured one; none ("": the SSH agent) where an SSH agent
// holds a key; otherwise the first of ~/.ssh/id_ed25519, id_ecdsa, id_rsa
// (DefaultKeyFiles) that has no passphrase, or "". locked names the ones
// passed over for a passphrase.
func (c *config) identityFile() (file string, locked []string) {
	if c.Identity != "" || userverify.AgentHasKeys() {
		return c.Identity, nil
	}
	return userverify.DefaultKeyFile(sshDirOf(c.SSHDir))
}

// noKey is why there is no SSH key to log in with.
func noKey(locked []string) error {
	msg := fmt.Sprintf("no SSH key: give -i KEYFILE, or run an SSH agent that holds your key, or have one of ~/.ssh/%s without a passphrase", strings.Join(userverify.DefaultKeyFiles, ", "))
	for _, l := range locked {
		msg += fmt.Sprintf("\n  %s has a passphrase, which %s does not ask for: load it into your SSH agent (ssh-add %s) or give -i KEYFILE", l, prog, l)
	}
	return errors.New(msg)
}

// loadConfig reads the configuration; a missing one is an error that says
// how to make it.
func loadConfig() (*config, error) {
	b, err := os.ReadFile(configPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("this machine is not set up: run %s auth login", prog)
	}
	if err != nil {
		return nil, err
	}
	var c config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", configPath(), err)
	}
	return &c, nil
}

// loadConfigOrEmpty is the configuration, or none: the old tools' flags
// then have to be given.
func loadConfigOrEmpty() *config {
	c, err := loadConfig()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "is not set up") {
			fail(0, "%v", err)
		}
		return &config{}
	}
	return c
}

// save writes the configuration whole, mode 0600.
func (c *config) save() error {
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir(), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), configPath())
}

// --- the policy directory ---------------------------------------------------

func policyDir() string { return filepath.Join(dir(), "policies") }

// policies are the files of the policy directory, all used where no
// -policy is given. None is no default: the command then says noPolicy.
func policies() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(policyDir(), "*.json"))
	sort.Strings(files)
	return files, err
}

func noPolicy() string {
	return fmt.Sprintf("no launch policy: give -policy FILE, or add the policies you accept once with: %s policy add FILE (every one in %s is used when -policy is not given)", prog, policyDir())
}

// policyCmd is "policy list | add FILE | rm NAME".
func policyCmd(args []string) int {
	usage := func() int { return fail(2, "usage: %s policy list | add FILE | rm NAME", prog) }
	if len(args) < 2 {
		return usage()
	}
	switch args[1] {
	case "list", "ls":
		if len(args) != 2 {
			return usage()
		}
		files, err := policies()
		if err != nil {
			return fail(1, "%v", err)
		}
		if len(files) == 0 {
			fmt.Fprintln(os.Stderr, noPolicy())
			return 0
		}
		for _, f := range files {
			p, err := attest.LoadPolicy(f)
			if err != nil {
				fmt.Printf("%-24s  NOT USABLE: %v\n", strings.TrimSuffix(filepath.Base(f), ".json"), err)
				continue
			}
			fmt.Printf("%-24s  policy %q, MRTD %.16s...\n", strings.TrimSuffix(filepath.Base(f), ".json"), p.Name, p.MRTD)
		}
		return 0
	case "add":
		if len(args) != 3 {
			return usage()
		}
		if _, err := attest.LoadPolicy(args[2]); err != nil {
			return fail(1, "%v", err)
		}
		b, err := os.ReadFile(args[2])
		if err != nil {
			return fail(1, "%v", err)
		}
		name := strings.TrimSuffix(filepath.Base(args[2]), ".json")
		dst := filepath.Join(policyDir(), name+".json")
		if old, err := os.ReadFile(dst); err == nil {
			if bytes.Equal(old, b) {
				fmt.Printf("%s is in the policy directory already: %s\n", name, dst)
				return 0
			}
			return fail(1, "the policy directory has another %s (%s): remove it first with: %s policy rm %s", name, dst, prog, name)
		}
		if err := os.MkdirAll(policyDir(), 0o700); err != nil {
			return fail(1, "%v", err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return fail(1, "%v", err)
		}
		fmt.Printf("%s added: %s. Without -policy, start, unlock, new and verify accept it.\n", name, dst)
		return 0
	case "rm", "remove":
		if len(args) != 3 {
			return usage()
		}
		name := strings.TrimSuffix(args[2], ".json")
		if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
			return fail(2, "%q is not a policy's name (policy list names them)", args[2])
		}
		if err := os.Remove(filepath.Join(policyDir(), name+".json")); err != nil {
			return fail(1, "%v", err)
		}
		fmt.Printf("%s removed from the policy directory.\n", name)
		return 0
	}
	return usage()
}
