package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func testKey(seed byte) []byte {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return append(sshagent.String([]byte("ssh-ed25519")), sshagent.String(private.Public().(ed25519.PublicKey))...)
}

func signPacket(key, data []byte) []byte {
	p := append([]byte{sshagent.SignRequest}, sshagent.String(key)...)
	p = append(p, sshagent.String(data)...)
	return append(p, 0, 0, 0, 0)
}

func signature(data []byte) []byte {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	inner := append(sshagent.String([]byte("ssh-ed25519")), sshagent.String(ed25519.Sign(private, data))...)
	return append([]byte{sshagent.SignResponse}, sshagent.String(inner)...)
}

func sessionBinding(key []byte) []byte {
	data := sshagent.String(key)
	data = append(data, sshagent.String([]byte("session"))...)
	data = append(data, sshagent.String([]byte("signature"))...)
	data = append(data, 1)
	return protocol.ExtensionPacket(protocol.AgentExtension, sshagent.SessionBind, data)
}

func signingPolicy(t *testing.T, key []byte, purposes []string, namespaces []string, max int) *policy.Policy {
	t.Helper()
	data, err := json.Marshal(policy.Policy{SSH: policy.SSHPolicy{Keys: []policy.KeyRule{{Fingerprint: sshagent.Fingerprint(key), Label: "test key", Approval: "biometric", Purposes: purposes, Namespaces: namespaces, MaxSignatures: max}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mockUpstream(t *testing.T, h *testAgent, handle func([]byte) []byte) *atomic.Int32 {
	t.Helper()
	ctx, cancel := context.WithCancel(h.ctx)
	var wg sync.WaitGroup
	var calls atomic.Int32
	h.server.dialUpstream = func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer server.Close()
			stop := context.AfterFunc(ctx, func() { server.Close() })
			defer stop()
			for {
				p, err := protocol.Read(server)
				if err != nil {
					return
				}
				calls.Add(1)
				if err := protocol.Write(server, handle(p)); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	t.Cleanup(func() { cancel(); wg.Wait() })
	return &calls
}

func roundTrip(t *testing.T, conn net.Conn, p []byte) []byte {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := protocol.Write(conn, p); err != nil {
		t.Fatal(err)
	}
	reply, err := protocol.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestSSHApprovesEverySignatureBeforeUpstream(t *testing.T) {
	entered := make(chan approval.Summary, 1)
	release := make(chan struct{})
	h, _ := startServer(t, func(ctx context.Context, s approval.Summary) error {
		entered <- s
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, "", time.Second)
	data := []byte("sign this data")
	h.server.Policy = signingPolicy(t, testKey(1), []string{"raw"}, nil, 0)
	calls := mockUpstream(t, h, func(p []byte) []byte {
		if !bytes.Equal(p, signPacket(testKey(1), data)) {
			t.Error("signing payload changed")
		}
		return signature(data)
	})
	conn := h.dial()
	defer conn.Close()
	for i := 0; i < 2; i++ {
		if err := protocol.Write(conn, signPacket(testKey(1), data)); err != nil {
			t.Fatal(err)
		}
		select {
		case s := <-entered:
			if s.Kind != "ssh-sign" || s.KeyFingerprint != sshagent.Fingerprint(testKey(1)) || s.Requirement != "biometric" || s.SigningBytes != len(data) || s.SigningPurpose != "raw" || s.KeyLabel != "test key" {
				t.Fatalf("wrong signing prompt: %+v", s)
			}
		case <-time.After(time.Second):
			t.Fatal("no signing approval")
		}
		if calls.Load() != int32(i) {
			t.Fatal("upstream contacted before local approval")
		}
		release <- struct{}{}
		p, err := protocol.Read(conn)
		if err != nil || !bytes.Equal(p, signature(data)) {
			t.Fatalf("signature: %v %v", p, err)
		}
		if !ed25519.Verify(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey), data, p[len(p)-ed25519.SignatureSize:]) {
			t.Fatal("returned signature does not verify")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("approval or upstream result was cached")
	}
}

func TestSSHFiltersKeysAndBlocksDirectHiddenKeyUse(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.Policy = signingPolicy(t, testKey(1), []string{"raw"}, nil, 0)
	calls := mockUpstream(t, h, func([]byte) []byte {
		return sshagent.EncodeIdentities([]sshagent.Identity{{Blob: testKey(1), Comment: []byte("visible")}, {Blob: testKey(2), Comment: []byte("hidden")}})
	})
	conn := h.dial()
	defer conn.Close()
	ids, err := sshagent.ParseIdentities(roundTrip(t, conn, []byte{11}))
	if err != nil || len(ids) != 1 || !bytes.Equal(ids[0].Blob, testKey(1)) {
		t.Fatalf("identities: %v %v", ids, err)
	}
	if !bytes.Equal(roundTrip(t, conn, signPacket(testKey(2), []byte("data"))), []byte{5}) {
		t.Fatal("hidden key signed data")
	}
	if calls.Load() != 1 || prompts.Load() != 0 {
		t.Fatal("hidden key reached upstream or local approval")
	}
}

func TestSSHBlocksMutationsAndUnknownExtensions(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.Policy.SSH.Management.Default = "deny"
	calls := mockUpstream(t, h, func([]byte) []byte { return []byte{6} })
	conn := h.dial()
	defer conn.Close()
	for _, p := range [][]byte{
		{1}, {7}, {8}, {9}, {17}, {18}, {19}, {20}, {21}, {22}, {23}, {25}, {26}, {255},
		{11, 0}, {13}, {13, 255, 255, 255, 255},
		protocol.ExtensionPacket(27, "unknown@extension", []byte("sign")),
		protocol.ExtensionPacket(27, "session-bind@openssh.com", []byte("invalid")),
	} {
		if !bytes.Equal(roundTrip(t, conn, p), []byte{5}) {
			t.Fatalf("forbidden request accepted: %v", p)
		}
	}
	if calls.Load() != 0 || prompts.Load() != 0 {
		t.Fatal("forbidden request reached upstream or approval")
	}
}

func TestSSHDeniedAndExpiredApprovalsNeverReachUpstream(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "expired"}[expired], func(t *testing.T) {
			h, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
				if expired {
					<-ctx.Done()
					return nil
				}
				return errors.New("denied")
			}, "", time.Second)
			h.server.ApprovalTimeout = 50 * time.Millisecond
			calls := mockUpstream(t, h, func([]byte) []byte { return signature([]byte("data")) })
			conn := h.dial()
			defer conn.Close()
			if !bytes.Equal(roundTrip(t, conn, signPacket(testKey(1), []byte("data"))), []byte{5}) {
				t.Fatal("failed approval produced a signature")
			}
			if calls.Load() != 0 {
				t.Fatal("failed approval reached upstream")
			}
		})
	}
}

func TestSSHDisconnectCancelsApproval(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	h, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}, "", time.Second)
	calls := mockUpstream(t, h, func([]byte) []byte { return signature([]byte("data")) })
	conn := h.dial()
	if err := protocol.Write(conn, signPacket(testKey(1), []byte("data"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no approval")
	}
	conn.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("signing approval survived disconnect")
	}
	if calls.Load() != 0 {
		t.Fatal("cancelled signing reached upstream")
	}
}

func TestSSHSignatureLimitAcrossConnections(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.Policy = signingPolicy(t, testKey(1), []string{"raw"}, nil, 1)
	calls := mockUpstream(t, h, func([]byte) []byte { return signature([]byte("data")) })
	for i := 0; i < 2; i++ {
		conn := h.dial()
		p := roundTrip(t, conn, signPacket(testKey(1), []byte("data")))
		conn.Close()
		if i == 0 && p[0] != 14 || i == 1 && !bytes.Equal(p, []byte{5}) {
			t.Fatalf("quota response: %v", p)
		}
	}
	if calls.Load() != 1 || prompts.Load() != 1 {
		t.Fatal("signature limit did not stop approval and upstream signing")
	}
}

func TestSSHFailedSignaturesReleaseQuota(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error {
		if prompts.Add(1) == 1 {
			return errors.New("denied")
		}
		return nil
	}, "", time.Second)
	h.server.Policy = signingPolicy(t, testKey(1), []string{"raw"}, nil, 1)
	var upstreamCalls atomic.Int32
	mockUpstream(t, h, func([]byte) []byte {
		if upstreamCalls.Add(1) == 1 {
			return []byte{5}
		}
		return signature([]byte("data"))
	})
	conn := h.dial()
	defer conn.Close()
	for i, want := range []byte{5, 5, 14, 5} {
		if got := roundTrip(t, conn, signPacket(testKey(1), []byte("data"))); got[0] != want {
			t.Fatalf("attempt %d: %v", i, got)
		}
	}
	if prompts.Load() != 3 || upstreamCalls.Load() != 2 {
		t.Fatal("failed approval or signature consumed quota")
	}
}

func TestSSHSigningUsesSharedApprovalGate(t *testing.T) {
	entered, release := make(chan struct{}, 3), make(chan struct{})
	h, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, "", time.Second)
	calls := mockUpstream(t, h, func(packet []byte) []byte {
		if packet[0] == 13 {
			return signature([]byte("data"))
		}
		return []byte{6}
	})
	first := h.dial()
	defer first.Close()
	if err := protocol.Write(first, signPacket(testKey(1), []byte("data"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no signing approval")
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.run(context.Background(), []string{"true"}, strings.NewReader(""), io.Discard, io.Discard)
		done <- err
	}()
	other := h.dial()
	defer other.Close()
	if err := protocol.Write(other, []byte{19}); err != nil {
		t.Fatal(err)
	}
	waitStage(t, h.server, "queued", 2)
	if calls.Load() != 0 || len(entered) != 0 {
		t.Fatal("queued request bypassed active approval")
	}
	close(release)
	if packet, err := protocol.Read(first); err != nil || packet[0] != 14 {
		t.Fatalf("signature: %v %v", packet, err)
	}
	if packet, err := protocol.Read(other); err != nil || !bytes.Equal(packet, []byte{6}) {
		t.Fatalf("management: %v %v", packet, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(entered) != 2 || calls.Load() != 2 {
		t.Fatal("queued approvals were lost")
	}
}

func TestCommandsUseProxyAgentEnvironment(t *testing.T) {
	h, _ := startServer(t, allow, "", time.Second)
	h.server.Socket = "/example/proxy.sock"
	var out bytes.Buffer
	code, err := h.run(context.Background(), []string{"sh", "-c", "printf '%s' \"$SSH_AUTH_SOCK\""}, strings.NewReader(""), &out, io.Discard)
	if err != nil || code != 0 || out.String() != h.server.Socket {
		t.Fatalf("command agent socket: %q %d %v", out.String(), code, err)
	}
}

func TestSSHNamespaceRestrictionBeforeApproval(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.Policy = signingPolicy(t, testKey(1), []string{"sshsig"}, []string{"git"}, 0)
	sshsig := func(namespace string) []byte {
		p := []byte("SSHSIG")
		for _, part := range [][]byte{[]byte(namespace), nil, []byte("sha256"), make([]byte, 32)} {
			p = append(p, sshagent.String(part)...)
		}
		return p
	}
	calls := mockUpstream(t, h, func(p []byte) []byte { request, _ := sshagent.ParseSign(p); return signature(request.Data) })
	conn := h.dial()
	defer conn.Close()
	for _, data := range [][]byte{[]byte("raw"), sshsig("file"), append(sshsig("git"), 1)} {
		if !bytes.Equal(roundTrip(t, conn, signPacket(testKey(1), data)), []byte{5}) {
			t.Fatal("disallowed signing purpose or namespace passed")
		}
	}
	if prompts.Load() != 0 || calls.Load() != 0 {
		t.Fatal("disallowed namespace reached approval or upstream")
	}
	if p := roundTrip(t, conn, signPacket(testKey(1), sshsig("git"))); p[0] != 14 {
		t.Fatalf("git signature denied: %v", p)
	}
	if prompts.Load() != 1 || calls.Load() != 1 {
		t.Fatal("allowed namespace bypassed approval")
	}
}

func TestSSHQuotaReservesPendingRequests(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.Policy = signingPolicy(t, testKey(1), []string{"raw"}, nil, 1)
	calls := mockUpstream(t, h, func([]byte) []byte { close(entered); <-release; return signature([]byte("data")) })
	first := h.dial()
	defer first.Close()
	if err := protocol.Write(first, signPacket(testKey(1), []byte("data"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no signing approval")
	}
	second := h.dial()
	defer second.Close()
	if p := roundTrip(t, second, signPacket(testKey(1), []byte("data"))); !bytes.Equal(p, []byte{5}) {
		t.Fatal("concurrent request bypassed quota")
	}
	if prompts.Load() != 1 {
		t.Fatal("pending upstream signature did not reserve quota")
	}
	releaseOnce.Do(func() { close(release) })
	if p, err := protocol.Read(first); err != nil || p[0] != 14 {
		t.Fatalf("first signature: %v %v", p, err)
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent quota produced extra signatures")
	}
}

func TestRunningCommandAllowsSSHApproval(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", 10*time.Second)
	mockUpstream(t, h, func([]byte) []byte { return signature([]byte("data")) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pids := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		_, err := h.run(ctx, []string{"sh", "-c", "printf '%s' $$; exec sleep 10"}, strings.NewReader(""), pidWriter{pid: pids}, io.Discard)
		done <- err
	}()
	select {
	case <-pids:
	case <-time.After(2 * time.Second):
		t.Fatal("command did not start")
	}
	conn := h.dial()
	defer conn.Close()
	if p := roundTrip(t, conn, signPacket(testKey(1), []byte("data"))); p[0] != 14 {
		t.Fatalf("running command blocked signing approval: %v", p)
	}
	if prompts.Load() != 2 {
		t.Fatal("command and signature did not receive separate approvals")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("command did not stop")
	}
}

func TestSSHUnpromptedKeySkipsApprovalButKeepsLimits(t *testing.T) {
	h, _ := startServer(t, func(context.Context, approval.Summary) error {
		t.Error("unprompted key asked for approval")
		return nil
	}, "", time.Second)
	data, _ := json.Marshal(policy.Policy{SSH: policy.SSHPolicy{Keys: []policy.KeyRule{{Fingerprint: sshagent.Fingerprint(testKey(1)), Approval: "none", Purposes: []string{"raw"}, MaxSignatures: 1}}}})
	var err error
	h.server.Policy, err = policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	calls := mockUpstream(t, h, func([]byte) []byte { return signature([]byte("data")) })
	for i, want := range []byte{sshagent.SignResponse, 5} {
		conn := h.dial()
		p := roundTrip(t, conn, signPacket(testKey(1), []byte("data")))
		conn.Close()
		if p[0] != want {
			t.Fatalf("signature %d: reply %v", i, p)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d", calls.Load())
	}
}
