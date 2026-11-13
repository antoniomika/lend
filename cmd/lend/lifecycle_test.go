package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	Socket   string
	AgentPID int
}

func TestSSHSubprocessFixture(t *testing.T) {
	marker := os.Getenv("LEND_TEST_SSH_FIXTURE")
	if marker == "" {
		t.Skip("subprocess fixture")
	}
	socket := os.Getenv("SSH_AUTH_SOCK")
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
	if response.Session != "fixture@agent-vm" {
		t.Fatalf("wrong local session %q", response.Session)
	}
	data, _ := json.Marshal(lifecycleFixture{Socket: socket, AgentPID: response.PID})
	if err := os.WriteFile(marker, data, 0600); err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, os.Stdin)
}

func TestSupervisedSessionLifecycle(t *testing.T) {
	// macOS TMPDIR is deep enough to push session sockets past the 104-byte sun_path limit.
	root, err := os.MkdirTemp("/tmp", "lend-")
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
	script := "#!/bin/sh\nexec " + quoted + " -test.run=^TestSSHSubprocessFixture$ --\n"
	if err := os.WriteFile(filepath.Join(fixtureDir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "policy.json")
	if err := os.WriteFile(config, []byte(`{"profiles":{"fixture":{"default":"deny","ssh":{"default":"deny"}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ssh-exit", "wrapper-exit"} {
		t.Run(mode, func(t *testing.T) {
			marker := filepath.Join(root, mode+".json")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := exec.CommandContext(ctx, executable, "ssh", "--config", config, "--profile", "fixture", "--upstream", filepath.Join(root, "upstream"), "--", "agent-vm")
			command.Env = append(os.Environ(), "PATH="+fixtureDir+":"+os.Getenv("PATH"), "XDG_RUNTIME_DIR="+root, "LEND_TEST_SSH_FIXTURE="+marker)
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
				if mode == "ssh-exit" && err != nil {
					t.Fatal(err)
				}
			case <-time.After(8 * time.Second):
				cancel()
				<-done
				t.Fatal("wrapper did not stop")
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
