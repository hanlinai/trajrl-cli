package userverify

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ClientPrefix starts the SSH identification string of every connection
// trajrl makes to the entry point. The entry point answers only clients
// that send it (sbxctl serve -ssh-clients trajrl, internal/control); that
// is a tidiness and UX gate, not a security boundary: keys and pinned host
// keys still decide access.
const ClientPrefix = "SSH-2.0-trajrl_"

var (
	versionMu     sync.Mutex
	clientVersion = ClientVersion("dev")
)

// ClientVersion is the SSH identification string for trajrl version v:
// ClientPrefix and v, with every character SSH does not allow in a
// software version (RFC 4253 4.2: printable US-ASCII, no space, no minus)
// replaced by '_'. "0.2.0" is SSH-2.0-trajrl_0.2.0.
func ClientVersion(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r > ' ' && r < 0x7f && r != '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		b.WriteString("unknown")
	}
	return ClientPrefix + b.String()
}

// SetVersion makes v (trajrl version's) the version DialEntry sends. The
// old programs (sbxkey, sbxverify, sbxapi) share DialEntry: they send
// ClientPrefix too, with "dev" unless their caller set one.
func SetVersion(v string) {
	versionMu.Lock()
	clientVersion = ClientVersion(v)
	versionMu.Unlock()
}

// sshClientVersion is the identification string DialEntry sends.
func sshClientVersion() string {
	versionMu.Lock()
	defer versionMu.Unlock()
	return clientVersion
}

// Proxy carries one connection for ssh's ProxyCommand ("trajrl proxy %h
// %p"): a direct-tcpip channel through the entry point to host:port (the
// entry point takes NAME.DOMAIN, NAME, or NAME-OWNER for a sandbox shared
// with you, and port 22 only), then in to the channel and the channel to
// out, until both ends are done. Nothing but the channel's bytes is
// written to out.
func Proxy(entry *ssh.Client, host, port string, in io.Reader, out io.Writer) error {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return fmt.Errorf("%q is not a port", port)
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("%q is not a host name", host)
	}
	conn, err := entry.Dial("tcp", host+":"+port)
	if err != nil {
		var oc *ssh.OpenChannelError
		if errors.As(err, &oc) {
			return fmt.Errorf("the entry point did not carry %s:%s: %s", host, port, oc.Message)
		}
		return fmt.Errorf("the entry point did not carry %s:%s: %w", host, port, err)
	}
	defer conn.Close()
	up := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, in)
		// ssh closed its side: say so, and keep reading what is still
		// on its way back.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		up <- err
	}()
	_, err = io.Copy(out, conn)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
