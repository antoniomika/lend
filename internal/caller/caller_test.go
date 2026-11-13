package caller

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCaptureProcessContext(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.1 54321 192.0.2.2 22")
	c := Capture(context.Background(), "cli")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.PID != os.Getpid() || c.ParentPID != os.Getppid() || c.UID == nil || *c.UID != uint32(os.Getuid()) {
		t.Fatal("captured process credentials differ")
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if c.Directory != dir || c.Source != "cli" || c.SSHConnection != "192.0.2.1 54321 192.0.2.2 22" {
		t.Fatal("caller environment was not captured")
	}
	if c.Host == "" || c.Executable == "" {
		t.Fatal("host or executable missing")
	}
}

func TestCaptureOmitsOversizedHints(t *testing.T) {
	t.Setenv("SSH_CONNECTION", strings.Repeat("x", 513))
	c := Capture(context.Background(), "mcp")
	if c.SSHConnection != "" {
		t.Fatal("oversized hint was included")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUnavailableLocalPeer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if LocalPeer(context.Background(), a) != nil {
		t.Fatal("in-memory transport fabricated socket credentials")
	}
}

func TestUnixLocalPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", path)
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("Unix sockets blocked by environment: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	peer := LocalPeer(context.Background(), server)
	if peer == nil || peer.PID != os.Getpid() {
		t.Fatalf("kernel peer PID mismatch: %+v", peer)
	}
	if peer.UID != nil && *peer.UID != uint32(os.Getuid()) {
		t.Fatal("kernel peer UID mismatch")
	}
}
