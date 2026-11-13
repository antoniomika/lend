package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/control"
	"github.com/antoniomika/lend/internal/device"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func waitStage(t *testing.T, s *Server, stage string, count int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		found := 0
		for _, entry := range s.Activity.Snapshot(false).Active {
			if entry.State == stage {
				found++
			}
		}
		if found >= count {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("did not find %d %s requests", count, stage)
		case <-time.After(time.Millisecond):
		}
	}
}

func waitNoStage(t *testing.T, s *Server, stage string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		found := false
		for _, entry := range s.Activity.Snapshot(false).Active {
			found = found || entry.State == stage
		}
		if !found {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%s requests did not leave", stage)
		case <-time.After(time.Millisecond):
		}
	}
}

func commandLeasePolicy(t *testing.T, lease *policy.Lease, secrets map[string]string, reader string) *policy.Policy {
	t.Helper()
	path, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(policy.Policy{SecretReader: reader, Commands: []policy.Rule{{Executable: path, Approval: "prompt", Lease: lease, Secrets: secrets}}})
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommandLeasesAreExplicitBoundedAndExact(t *testing.T) {
	for _, grant := range []bool{false, true} {
		t.Run(map[bool]string{false: "once", true: "lease"}[grant], func(t *testing.T) {
			h, _ := startServer(t, allow, "", time.Second)
			h.server.Policy = commandLeasePolicy(t, &policy.Lease{Duration: "1m", Uses: 3}, nil, "")
			h.server.DeviceCheck = func(context.Context) (device.State, error) { return device.State{Unlocked: true}, nil }
			var prompts atomic.Int32
			h.server.Decide = func(_ context.Context, s approval.Summary) (approval.Decision, error) {
				prompts.Add(1)
				if s.Lease == nil {
					t.Error("lease was not offered")
				}
				return approval.Decision{Lease: grant}, nil
			}
			run := func(value string) {
				var out bytes.Buffer
				code, err := h.run(context.Background(), []string{"sh", "-c", "printf %s " + value}, strings.NewReader(""), &out, io.Discard)
				if err != nil || code != 0 || out.String() != value {
					t.Fatalf("%d %v %q", code, err, out.String())
				}
			}
			for range 3 {
				run("same")
			}
			expected := int32(3)
			if grant {
				expected = 1
			}
			if prompts.Load() != expected {
				t.Fatalf("prompts=%d want %d", prompts.Load(), expected)
			}
			run("same")
			if prompts.Load() != expected+1 {
				t.Fatal("exhausted lease reused")
			}
			run("different")
			if prompts.Load() != expected+2 {
				t.Fatal("lease changed arguments")
			}
		})
	}
}

func TestLeaseExpiryLockAndRevocation(t *testing.T) {
	for _, change := range []string{"expiry", "lock", "unknown-state", "clear", "pause", "event"} {
		t.Run(change, func(t *testing.T) {
			h, _ := startServer(t, allow, "", time.Second)
			h.server.Policy = commandLeasePolicy(t, &policy.Lease{Duration: "1m", Uses: 10}, nil, "")
			var locked, unknown, event atomic.Bool
			h.server.DeviceCheck = func(context.Context) (device.State, error) {
				if unknown.Load() {
					return device.State{}, errors.New("unavailable")
				}
				return device.State{Unlocked: !locked.Load(), Changed: event.Swap(false)}, nil
			}
			var prompts atomic.Int32
			h.server.Decide = func(context.Context, approval.Summary) (approval.Decision, error) {
				prompts.Add(1)
				return approval.Decision{Lease: true}, nil
			}
			run := func() {
				code, err := h.run(context.Background(), []string{"sh", "-c", "true"}, strings.NewReader(""), io.Discard, io.Discard)
				if code != 0 || err != nil {
					t.Fatalf("%d %v", code, err)
				}
			}
			run()
			run()
			if prompts.Load() != 1 {
				t.Fatal("lease not reused")
			}
			switch change {
			case "expiry":
				h.server.leaseMu.Lock()
				for k, v := range h.server.leases {
					v.Expires = time.Now().Add(-time.Second)
					h.server.leases[k] = v
				}
				h.server.leaseMu.Unlock()
			case "lock":
				locked.Store(true)
				h.server.unlocked(context.Background())
				locked.Store(false)
			case "unknown-state":
				unknown.Store(true)
				h.server.unlocked(context.Background())
				unknown.Store(false)
			case "event":
				event.Store(true)
			case "clear":
				h.server.Control(control.Request{Action: "clear-leases"})
			case "pause":
				h.server.Control(control.Request{Action: "pause"})
				h.server.Control(control.Request{Action: "resume"})
			}
			run()
			if prompts.Load() != 2 {
				t.Fatalf("lease survived %s", change)
			}
		})
	}
}

func TestLeaseUnavailableStillRequiresApproval(t *testing.T) {
	h, _ := startServer(t, allow, "", time.Second)
	h.server.Policy = commandLeasePolicy(t, &policy.Lease{Duration: "1m", Uses: 3}, nil, "")
	h.server.DeviceCheck = func(context.Context) (device.State, error) { return device.State{}, errors.New("unsupported") }
	var prompts atomic.Int32
	h.server.Decide = func(_ context.Context, s approval.Summary) (approval.Decision, error) {
		prompts.Add(1)
		if s.Lease != nil {
			t.Error("lease offered without lock tracking")
		}
		return approval.Decision{Lease: true}, nil
	}
	for range 2 {
		if _, err := h.run(context.Background(), []string{"sh", "-c", "true"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if prompts.Load() != 2 || len(h.server.leaseViews()) != 0 {
		t.Fatal("unsupported lock tracking granted a lease")
	}
}

func TestUnsupervisedAgentNeverOffersLeases(t *testing.T) {
	h, _ := startServer(t, allow, "", time.Second)
	h.server.SessionBound = false
	h.server.Policy = commandLeasePolicy(t, &policy.Lease{Duration: "1m", Uses: 3}, nil, "")
	h.server.DeviceCheck = func(context.Context) (device.State, error) { return device.State{Unlocked: true}, nil }
	var prompts atomic.Int32
	h.server.Decide = func(_ context.Context, s approval.Summary) (approval.Decision, error) {
		prompts.Add(1)
		if s.Lease != nil {
			t.Error("unmanaged SSH lifetime offered a lease")
		}
		return approval.Decision{Lease: true}, nil
	}
	for range 2 {
		if _, err := h.run(context.Background(), []string{"sh", "-c", "true"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if prompts.Load() != 2 {
		t.Fatal("unmanaged agent reused approval")
	}
}

func TestSigningLeasesRespectQuotaAndNamespace(t *testing.T) {
	h, _ := startServer(t, allow, "", time.Second)
	h.server.Policy = signingPolicy(t, testKey(1), []string{"sshsig"}, []string{"git", "file"}, 3)
	h.server.Policy.SSH.Keys[0].Lease = &policy.Lease{Duration: "1m", Uses: 10}
	h.server.DeviceCheck = func(context.Context) (device.State, error) { return device.State{Unlocked: true}, nil }
	var prompts atomic.Int32
	h.server.Decide = func(context.Context, approval.Summary) (approval.Decision, error) {
		prompts.Add(1)
		return approval.Decision{Lease: true}, nil
	}
	calls := mockUpstream(t, h, func(packet []byte) []byte { request, _ := sshagent.ParseSign(packet); return signature(request.Data) })
	request := func(namespace string) []byte {
		data := []byte("SSHSIG")
		for _, part := range [][]byte{[]byte(namespace), nil, []byte("sha256"), make([]byte, 32)} {
			data = append(data, sshagent.String(part)...)
		}
		return signPacket(testKey(1), data)
	}
	for i, namespace := range []string{"git", "git", "file", "git"} {
		conn := h.dial()
		reply := roundTrip(t, conn, request(namespace))
		conn.Close()
		if i < 3 && reply[0] != 14 {
			t.Fatal("valid signature refused")
		}
		if i == 3 && reply[0] != 5 {
			t.Fatal("lease bypassed signature quota")
		}
	}
	if prompts.Load() != 2 || calls.Load() != 3 {
		t.Fatalf("prompts=%d signatures=%d", prompts.Load(), calls.Load())
	}
}

func TestCredentialReaderFailuresDoNotExposeValues(t *testing.T) {
	for _, script := range []string{"printf hidden-fixture >&2; exit 1", "printf '\\000'", "head -c 65537 /dev/zero"} {
		t.Run(script[:6], func(t *testing.T) {
			h, dir := startServer(t, allow, "", time.Second)
			reader := filepath.Join(dir, "op-fixture")
			if err := os.WriteFile(reader, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			h.server.Policy = commandLeasePolicy(t, nil, map[string]string{"TOKEN": "op://vault/item/field"}, reader)
			var out, stderr bytes.Buffer
			_, err := h.run(context.Background(), []string{"sh", "-c", "printf should-not-run"}, strings.NewReader(""), &out, &stderr)
			if err == nil || out.Len() != 0 || stderr.Len() != 0 || strings.Contains(err.Error(), "hidden-fixture") {
				t.Fatalf("credential failure leaked output: %v %q %q", err, out.String(), stderr.String())
			}
		})
	}
}

func TestPauseAndRevokeCancelQueuedAndRunningCommands(t *testing.T) {
	h, _ := startServer(t, allow, "", 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.run(ctx, []string{"sh", "-c", "exec sleep 10"}, strings.NewReader(""), io.Discard, io.Discard)
		done <- err
	}()
	waitStage(t, h.server, "running", 1)
	response := h.server.Control(control.Request{Action: "status"})
	id := ""
	for _, entry := range response.Active {
		if entry.Kind == "command" {
			id = entry.ID
		}
	}
	if id == "" {
		t.Fatal("running command missing from status")
	}
	h.server.Control(control.Request{Action: "revoke", ID: id})
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked command succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("revoke did not stop execution")
	}
	h.server.Control(control.Request{Action: "pause"})
	if _, err := h.run(context.Background(), []string{"true"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("paused agent ran a command")
	}
	h.server.Control(control.Request{Action: "resume"})
	if _, err := h.run(context.Background(), []string{"true"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestQueuedRequestCancellationDoesNotPrompt(t *testing.T) {
	entered := make(chan struct{}, 2)
	h, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}, "", time.Second)
	first := h.dial()
	defer first.Close()
	packet, _ := protocol.EncodeRequest(protocol.Request{Args: []string{"true"}})
	if err := protocol.Write(first, packet); err != nil {
		t.Fatal(err)
	}
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.run(ctx, []string{"true"}, strings.NewReader(""), io.Discard, io.Discard)
		done <- err
	}()
	waitStage(t, h.server, "queued", 1)
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled request succeeded")
	}
	// The client returns before the server sees the disconnect, so wait for the queue to drop it.
	waitNoStage(t, h.server, "queued")
	first.Close()
	select {
	case <-entered:
		t.Fatal("cancelled queue entry prompted")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestQueueExpiryDoesNotOpenAnApprovalDialog(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.ApprovalTimeout = 30 * time.Millisecond
	h.server.approvals <- struct{}{}
	defer func() { <-h.server.approvals }()
	if _, err := h.run(context.Background(), []string{"true"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expired queued request succeeded")
	}
	waitHistory(t, h.server, 1)
	if prompts.Load() != 0 || h.server.Activity.Snapshot(true).History[0].State != "expired" {
		t.Fatal("expired queue entry prompted or lost its outcome")
	}
}

func TestCredentialInjectionRunsAfterApprovalAndStaysLocal(t *testing.T) {
	h, dir := startServer(t, allow, "", time.Second)
	marker := filepath.Join(dir, "reads")
	reader := filepath.Join(dir, "op-fixture")
	script := "#!/bin/sh\nprintf read >> '" + marker + "'\nprintf fixture-secret-value"
	if err := os.WriteFile(reader, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	h.server.Policy = commandLeasePolicy(t, nil, map[string]string{"SERVICE_TOKEN": "op://vault/item/token"}, reader)
	var prompts atomic.Int32
	h.server.Approve = func(_ context.Context, s approval.Summary) error {
		prompts.Add(1)
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Error("credential read before approval")
		}
		if strings.Contains(s.String(), "fixture-secret-value") || !strings.Contains(s.String(), "SERVICE_TOKEN") {
			t.Error("incorrect credential prompt")
		}
		return nil
	}
	var out bytes.Buffer
	code, err := h.run(context.Background(), []string{"sh", "-c", `test "${#SERVICE_TOKEN}" -eq 20 && printf authenticated`}, strings.NewReader(""), &out, io.Discard)
	if code != 0 || err != nil || out.String() != "authenticated" || prompts.Load() != 1 {
		t.Fatalf("%d %v %q", code, err, out.String())
	}
	waitHistory(t, h.server, 1)
	response := h.server.Control(control.Request{Action: "history"})
	data, _ := json.Marshal(response.History)
	for _, secret := range []string{"fixture-secret-value", "op://vault", "SERVICE_TOKEN"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("history leaked %s", secret)
		}
	}
	os.Remove(marker)
	h.server.Approve = func(context.Context, approval.Summary) error { return errors.New("denied") }
	if _, err := h.run(context.Background(), []string{"sh", "-c", "true"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("denial ignored")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("denied request retrieved credentials")
	}
}

func waitHistory(t *testing.T, s *Server, count int) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		if len(s.Activity.Snapshot(true).History) >= count {
			return
		}
		select {
		case <-deadline:
			t.Fatal("missing completed history")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestCredentialReaderReceivesConfiguredArgs(t *testing.T) {
	h, dir := startServer(t, allow, "", time.Second)
	argv := filepath.Join(dir, "argv")
	reader := filepath.Join(dir, "reader")
	script := "#!/bin/sh\nfor arg; do printf '%s\\n' \"$arg\" >> '" + argv + "'; done\nprintf value"
	if err := os.WriteFile(reader, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	h.server.Policy = commandLeasePolicy(t, nil, map[string]string{"TOKEN": "service name"}, reader)
	h.server.Policy.SecretReaderArgs = []string{"get", "--raw"}
	var out bytes.Buffer
	if code, err := h.run(context.Background(), []string{"sh", "-c", "printf %s \"$TOKEN\""}, strings.NewReader(""), &out, io.Discard); err != nil || code != 0 || out.String() != "value" {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	got, err := os.ReadFile(argv)
	if err != nil || string(got) != "get\n--raw\nservice name\n" {
		t.Fatalf("reader argv=%q err=%v", got, err)
	}
}
