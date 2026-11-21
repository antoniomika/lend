package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/agent"
	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/doctor"
)

func TestCLIEnvironmentDefaults(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "lend-env-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	upstream, err := agent.Listen(filepath.Join(root, "upstream"))
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skip("environment denies Unix sockets")
		}
		t.Fatal(err)
	}
	defer upstream.Close()
	executable := filepath.Join(root, "lend")
	if output, err := exec.Command("go", "build", "-buildvcs=false", "-o", executable, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	pwd, err := exec.LookPath("pwd")
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "policy.json")
	data, _ := json.Marshal(map[string]any{"profiles": map[string]any{"fixture": map[string]any{"commands": []map[string]any{{"executable": pwd, "approval": "none"}}}}})
	if err := os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "LEND_") && !strings.HasPrefix(entry, "_LEND_") {
			env = append(env, entry)
		}
	}
	env = append(env, "HOME="+home, "XDG_RUNTIME_DIR="+root, "LEND_CONFIG="+config, "LEND_PROFILE=fixture", "LEND_UPSTREAM="+filepath.Join(root, "upstream"), "LEND_DIR=/missing", "LEND_SILENT=true")
	command := func(args ...string) *exec.Cmd {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Env = append([]string(nil), env...)
		return cmd
	}
	startAgent := func(t *testing.T, socket string, extraEnv []string, args ...string) {
		t.Helper()
		cmd := command(append([]string{"agent", "--socket", socket, "--dir=", "--_ready-fd=3"}, args...)...)
		cmd.Env = append(cmd.Env, extraEnv...)
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		cmd.ExtraFiles = []*os.File{writer}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cmd.Process.Signal(syscall.SIGTERM)
			if err := cmd.Wait(); err != nil {
				t.Errorf("agent failed: %v %s", err, &stderr)
			}
			if stderr.Len() != 0 {
				t.Errorf("silent agent wrote stderr: %q", &stderr)
			}
		})
		writer.Close()
		if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		ready := make([]byte, 6)
		if _, err := io.ReadFull(reader, ready); err != nil || string(ready) != "ready\n" {
			t.Fatalf("agent failed to become ready: %q %v", ready, err)
		}
	}
	socket := filepath.Join(root, "proxy.sock")
	startAgent(t, socket, nil)
	var output bytes.Buffer
	code, err := client.Run(context.Background(), socket, []string{pwd}, strings.NewReader(""), &output, io.Discard)
	if err != nil || code != 0 || strings.TrimSpace(output.String()) != home {
		t.Fatalf("environment policy/profile or empty directory override failed: %d %v %q", code, err, &output)
	}
	t.Run("explain", func(t *testing.T) {
		output, err := command("explain", "--", pwd).CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte(`"allowed":true`)) {
			t.Fatalf("explain ignored environment policy: %v %s", err, output)
		}
	})
	t.Run("doctor-local", func(t *testing.T) {
		output, _ := command("doctor", "--dir=", "--upstream", filepath.Join(root, "missing"), "--json").Output()
		var report doctor.Report
		if err := json.Unmarshal(output, &report); err != nil {
			t.Fatal(err)
		}
		checks := map[string]doctor.Check{}
		for _, check := range report.Checks {
			checks[check.Name] = check
		}
		if report.Mode != "local" || checks["policy"].Status != "ok" || checks["directory"].Status != "ok" || checks["directory"].Message != home {
			t.Fatalf("doctor ignored environment defaults or empty directory override: %s", output)
		}
	})
	t.Run("doctor-remote", func(t *testing.T) {
		cmd := command("doctor", "--remote", "--socket", socket, "--json")
		cmd.Env = append(cmd.Env, "LEND_CONFIG=/missing", "LEND_PROFILE=missing", "LEND_APPROVAL=invalid", "LEND_DIR=/missing")
		output, err := cmd.CombinedOutput()
		var report doctor.Report
		if err != nil || json.Unmarshal(output, &report) != nil || report.Mode != "remote" || !report.Healthy() {
			t.Fatalf("remote doctor used local environment defaults: %v %s", err, output)
		}
	})
	t.Run("allow-all", func(t *testing.T) {
		startAgent(t, filepath.Join(root, "allow.sock"), []string{"LEND_CONFIG=/missing", "LEND_PROFILE=missing"}, "--allow-all")
	})
	t.Run("ssh-local", func(t *testing.T) {
		if _, err := exec.LookPath("ssh"); err != nil {
			t.Skip("OpenSSH is unavailable")
		}
		for _, args := range [][]string{{"-V"}, {"-Q", "cipher"}, {"-G", "-F", "/dev/null", "example.invalid"}, {"--foo", "host"}, {"-z", "host"}, {"host", "-p"}} {
			cmd := command(append([]string{"ssh"}, args...)...)
			cmd.Env = append(cmd.Env, "LEND_CONFIG=", "LEND_PROFILE=", "LEND_SILENT=invalid", "LEND_UPSTREAM=/missing")
			output, err := cmd.CombinedOutput()
			invalid := args[0] == "--foo" || args[0] == "-z" || args[0] == "host"
			if (err != nil) != invalid || bytes.Contains(output, []byte("lend:")) || bytes.Contains(output, []byte("lend agent")) {
				t.Errorf("SSH passthrough %q: %v %s", args, err, output)
			}
		}
	})
	t.Run("ssh-option-injection", func(t *testing.T) {
		if _, err := exec.LookPath("ssh"); err != nil {
			t.Skip("OpenSSH is unavailable")
		}
		marker := filepath.Join(root, "executed")
		cmd := command("ssh", "--", "-oProxyCommand=touch "+marker, "host")
		output, err := cmd.CombinedOutput()
		if err == nil || bytes.Contains(output, []byte("lend:")) {
			t.Fatalf("invalid hostname was not rejected by SSH: %v %s", err, output)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("SSH executed an option supplied as a hostname: %v", err)
		}
	})
}
