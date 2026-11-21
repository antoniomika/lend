package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSessionSSHArgumentsUseOnlyTheIsolatedSocket(t *testing.T) {
	args := sessionSSHArgs([]string{"agent-vm", "printf", "hello"})
	for _, expected := range []string{"IdentityAgent=SSH_AUTH_SOCK", "ForwardAgent=${_LEND_SESSION_SOCKET}", "ControlMaster=no", "ControlPath=none", "ControlPersist=no", "ForkAfterAuthentication=no"} {
		if !slices.Contains(args, expected) {
			t.Fatalf("missing %s", expected)
		}
	}
	if !slices.Equal(args[len(args)-3:], []string{"agent-vm", "printf", "hello"}) {
		t.Fatal("remote command arguments changed")
	}
}

func TestSessionSSHOptionsWithOpenSSH(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is unavailable")
	}
	socket := filepath.Join(t.TempDir(), "proxy %r %z ${USER} socket")
	if err := os.WriteFile(socket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	args := sessionSSHArgs([]string{"-G", "-F", "/dev/null", "-T", "-p2222", "-l", "fixture", "-J", "jump.invalid", "-oIdentityAgent=/other", "-oForwardAgent=/other", "-oControlMaster=yes", "-oControlPath=/other", "-oControlPersist=yes", "-oForkAfterAuthentication=yes", "example.invalid"})
	command := exec.Command(ssh, args...)
	command.Env = append(os.Environ(), "_LEND_SESSION_SOCKET="+socket)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G: %v\n%s", err, output)
	}
	for _, line := range []string{"hostname example.invalid", "user fixture", "port 2222", "proxyjump jump.invalid", "identityagent SSH_AUTH_SOCK", "forwardagent " + socket, "controlmaster false", "controlpersist no", "forkafterauthentication no"} {
		if !slices.Contains(strings.Split(string(output), "\n"), line) {
			t.Errorf("missing %q in ssh -G output:\n%s", line, output)
		}
	}
	if strings.Contains(string(output), "/other") {
		t.Fatalf("session isolation was overridden:\n%s", output)
	}
}

func TestExplainAndValidationNeverExecuteACommand(t *testing.T) {
	path, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(config, []byte(`{"default":"allow","profiles":{"restricted":{"default":"deny"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	code, err := run(context.Background(), []string{"explain", "--config", config, "--", path})
	if code != 0 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	code, err = run(context.Background(), []string{"explain", "--config", config, "--profile", "restricted", "--", path})
	if code != 1 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	for _, args := range [][]string{{"ssh", "--config", config, "-f", "agent-vm"}, {"revoke"}, {"pause", "--watch"}, {"explain", "--config", config}} {
		code, err := run(context.Background(), args)
		if code != 2 || err == nil {
			t.Fatalf("invalid command accepted: %v, %d %v", args, code, err)
		}
	}
}
