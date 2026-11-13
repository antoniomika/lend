package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestSessionSSHArgumentsUseOnlyTheIsolatedSocket(t *testing.T) {
	args := sessionSSHArgs([]string{"agent-vm", "printf", "hello"})
	for _, expected := range []string{"IdentityAgent=SSH_AUTH_SOCK", "ForwardAgent=yes", "ControlMaster=no", "ControlPath=none", "ControlPersist=no", "ForkAfterAuthentication=no"} {
		if !slices.Contains(args, expected) {
			t.Fatalf("missing %s", expected)
		}
	}
	if !slices.Equal(args[len(args)-4:], []string{"--", "agent-vm", "printf", "hello"}) {
		t.Fatal("remote command arguments changed")
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
	for _, args := range [][]string{{"ssh", "--config", config, "--", "-oForwardAgent=/original"}, {"revoke"}, {"pause", "--watch"}, {"explain", "--config", config}} {
		code, err := run(context.Background(), args)
		if code != 2 || err == nil {
			t.Fatalf("invalid command accepted: %v, %d %v", args, code, err)
		}
	}
}
