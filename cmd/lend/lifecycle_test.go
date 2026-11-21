package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/agent"
	"github.com/antoniomika/lend/internal/control"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

type lifecycleFixture struct {
	Socket     string
	AgentPID   int
	Args       []string
	AuthSocket string
}

func TestSSHSubprocessFixture(t *testing.T) {
	marker := os.Getenv("LEND_TEST_SSH_FIXTURE")
	if marker == "" {
		t.Skip("subprocess fixture")
	}
	socket := os.Getenv("_LEND_SESSION_SOCKET")
	if socket == "" {
		t.Fatal("missing forwarded proxy socket")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := protocol.Write(conn, []byte{sshagent.RequestIdentities}); err != nil {
		t.Fatal(err)
	}
	reply, err := protocol.Read(conn)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	identities, err := sshagent.ParseIdentities(reply)
	if err != nil || len(identities) != 0 {
		t.Fatal("session policy was not applied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := control.Call(ctx, socket+".control", control.Request{Action: "status"})
	if err != nil {
		t.Fatal(err)
	}
	wantSession := "fixture@agent-vm"
	if os.Getenv("LEND_TEST_EMPTY_PROFILE") != "" {
		wantSession = "agent-vm"
	}
	if response.Session != wantSession {
		t.Fatalf("wrong local session %q", response.Session)
	}
	data, _ := json.Marshal(lifecycleFixture{Socket: socket, AgentPID: response.PID, Args: os.Args[3:], AuthSocket: os.Getenv("SSH_AUTH_SOCK")})
	if err := os.WriteFile(marker, data, 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "fixture ssh stdout")
	fmt.Fprintln(os.Stderr, "fixture ssh stderr")
	io.Copy(io.Discard, os.Stdin)
	if os.Getenv("LEND_TEST_SSH_EXIT") != "" {
		os.Exit(23)
	}
}

func TestSupervisedSessionLifecycle(t *testing.T) {
	// macOS TMPDIR is deep enough to push session sockets past the 104-byte sun_path limit.
	root, err := os.MkdirTemp("/tmp", "lend-%r-${USER}-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	upstream, err := agent.Listen(filepath.Join(root, "upstream"))
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skip("environment denies Unix sockets")
		}
		t.Fatal(err)
	}
	defer upstream.Close()
	// XDG_RUNTIME_DIR is root, so root/lend is the session socket directory.
	executable := filepath.Join(root, "lend-bin")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", executable, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fixtureDir := filepath.Join(root, "fixture")
	if err := os.Mkdir(fixtureDir, 0700); err != nil {
		t.Fatal(err)
	}
	quoted := "'" + strings.ReplaceAll(testExecutable, "'", "'\"'\"'") + "'"
	script := "#!/bin/sh\nexec " + quoted + " -test.run=^TestSSHSubprocessFixture$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(fixtureDir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "policy.json")
	if err := os.WriteFile(config, []byte(`{"profiles":{"fixture":{"default":"deny","ssh":{"default":"deny"}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ssh-exit", "wrapper-exit", "silent", "flag-overrides-env", "ssh-error", "system-agent", "system-agent-env", "empty-profile", "relative-runtime", "remote-options"} {
		t.Run(mode, func(t *testing.T) {
			marker := filepath.Join(root, mode+".json")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sshArgs := []string{"-vv", "-p", "2222", "-Jjump", "--", "agent-vm", "printf", "%s", "a b", "--config", "remote.json"}
			if mode == "remote-options" {
				sshArgs = []string{"--", "agent-vm", "-V", "-f", "-p", "2222"}
			}
			args := []string{"ssh", "--config", config, "--profile", "fixture", "--upstream", filepath.Join(root, "upstream")}
			if mode == "silent" || mode == "wrapper-exit" || mode == "ssh-error" {
				args = []string{"ssh"}
			} else if mode == "flag-overrides-env" {
				args = append(args, "--silent=false", "--system-agent=false")
			} else if mode == "system-agent" {
				args = append(args, "--system-agent")
			} else if mode == "empty-profile" {
				args = []string{"ssh", "--profile="}
			}
			command := exec.CommandContext(ctx, executable, append(args, sshArgs...)...)
			command.Env = append(os.Environ(), "PATH="+fixtureDir+":"+os.Getenv("PATH"), "XDG_RUNTIME_DIR="+root, "LEND_TEST_SSH_FIXTURE="+marker)
			command.Env = append(command.Env, "LEND_CONFIG="+config, "LEND_PROFILE=fixture", "LEND_UPSTREAM="+filepath.Join(root, "upstream"), "LEND_SILENT=true", "LEND_SYSTEM_AGENT=false")
			if mode == "ssh-exit" {
				command.Env = append(command.Env, "LEND_SILENT=false")
			}
			if mode == "flag-overrides-env" {
				command.Env = append(command.Env, "LEND_CONFIG=/missing", "LEND_PROFILE=missing", "LEND_UPSTREAM=/missing", "LEND_SYSTEM_AGENT=true")
			}
			if mode == "system-agent-env" {
				command.Env = append(command.Env, "LEND_SYSTEM_AGENT=true")
			}
			if mode == "ssh-error" {
				command.Env = append(command.Env, "LEND_TEST_SSH_EXIT=23")
			}
			if mode == "empty-profile" {
				command.Env = append(command.Env, "LEND_TEST_EMPTY_PROFILE=1")
			}
			if mode == "relative-runtime" {
				command.Dir = root
				command.Env = append(command.Env, "XDG_RUNTIME_DIR=runtime%r-${USER}")
			}
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			command.WaitDelay = time.Second
			input, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			var fixture lifecycleFixture
			deadline := time.After(8 * time.Second)
			for fixture.Socket == "" {
				data, err := os.ReadFile(marker)
				if err == nil {
					var ready lifecycleFixture
					if json.Unmarshal(data, &ready) == nil {
						fixture = ready
					}
				}
				if fixture.Socket != "" {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("wrapper exited before readiness: %v", err)
				case <-deadline:
					cancel()
					input.Close()
					<-done
					t.Fatal("session did not start")
				case <-time.After(5 * time.Millisecond):
				}
			}
			if !slices.Equal(fixture.Args, sessionSSHArgs(sshArgs)) {
				t.Fatalf("SSH arguments changed: %q", fixture.Args)
			}
			if !filepath.IsAbs(fixture.Socket) {
				t.Fatalf("forwarded socket path is relative: %q", fixture.Socket)
			}
			wantAuthSocket := fixture.Socket
			if mode == "system-agent" || mode == "system-agent-env" {
				wantAuthSocket = filepath.Join(root, "upstream")
			}
			if fixture.AuthSocket != wantAuthSocket {
				t.Fatalf("wrong authentication socket: got %q want %q", fixture.AuthSocket, wantAuthSocket)
			}
			defer func() {
				stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
				defer stopCancel()
				response, err := control.Call(stopCtx, fixture.Socket+".control", control.Request{Action: "status"})
				if err == nil && response.PID == fixture.AgentPID && response.Session == "fixture@agent-vm" {
					syscall.Kill(fixture.AgentPID, syscall.SIGTERM)
				}
			}()
			if mode == "wrapper-exit" {
				command.Process.Kill()
			}
			input.Close()
			select {
			case err := <-done:
				if mode == "ssh-error" {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 23 {
						t.Fatalf("SSH exit status changed: %v", err)
					}
				} else if mode != "wrapper-exit" && err != nil {
					t.Fatalf("wrapper failed: %v %s", err, &stderr)
				}
			case <-time.After(8 * time.Second):
				cancel()
				<-done
				t.Fatal("wrapper did not stop")
			}
			if mode != "wrapper-exit" {
				if !strings.Contains(stdout.String(), "fixture ssh stdout") || !strings.Contains(stderr.String(), "fixture ssh stderr") {
					t.Fatalf("SSH output lost: stdout=%q stderr=%q", &stdout, &stderr)
				}
				banner := strings.Contains(stderr.String(), "lend agent listening") && strings.Contains(stderr.String(), "lend session")
				wantBanner := mode == "ssh-exit" || mode == "flag-overrides-env"
				if banner != wantBanner || (!wantBanner && strings.Contains(stderr.String(), "lend")) {
					t.Fatalf("unexpected lend startup output: %q", &stderr)
				}
			}
			deadline = time.After(5 * time.Second)
			for {
				_, socketErr := os.Lstat(fixture.Socket)
				_, controlErr := os.Lstat(fixture.Socket + ".control")
				if os.IsNotExist(socketErr) && os.IsNotExist(controlErr) {
					break
				}
				select {
				case <-deadline:
					t.Fatal("session sockets survived wrapper exit")
				case <-time.After(5 * time.Millisecond):
				}
			}
		})
	}
}
