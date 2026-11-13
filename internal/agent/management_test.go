package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func managementPacket(kind byte, fields ...[]byte) []byte {
	p := []byte{kind}
	for _, field := range fields {
		p = append(p, sshagent.String(field)...)
	}
	return p
}

func addFixture() []byte {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	return managementPacket(17, []byte("ssh-ed25519"), private[32:], private, []byte("fixture"))
}

func managementPolicy(t *testing.T, rules ...policy.ManagementRule) *policy.Policy {
	t.Helper()
	data, _ := json.Marshal(policy.Policy{SSH: policy.SSHPolicy{Management: policy.ManagementPolicy{Operations: rules}}})
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagementApprovesBeforeEveryForward(t *testing.T) {
	for _, tc := range []struct {
		name      string
		packet    []byte
		operation string
	}{
		{"add key", addFixture(), "add-key"},
		{"remove key", managementPacket(18, testKey(1)), "remove-key"},
		{"remove all", []byte{19}, "remove-all-keys"},
		{"lock", managementPacket(22, []byte("fixture-hidden-passphrase")), "lock"},
		{"unlock", managementPacket(23, []byte("fixture-hidden-passphrase")), "unlock"},
		{"load provider", managementPacket(20, []byte("/example/provider.so"), []byte("fixture-hidden-pin")), "add-provider"},
		{"unload provider", managementPacket(21, []byte("/example/provider.so"), nil), "remove-provider"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			h.server.Policy = managementPolicy(t, policy.ManagementRule{Operation: tc.operation, Approval: "biometric"})
			calls := mockUpstream(t, h, func(p []byte) []byte {
				if !bytes.Equal(p, tc.packet) {
					t.Error("management packet changed")
				}
				return []byte{6}
			})
			conn := h.dial()
			defer conn.Close()
			for i := 0; i < 2; i++ {
				if err := protocol.Write(conn, tc.packet); err != nil {
					t.Fatal(err)
				}
				select {
				case s := <-entered:
					if s.Kind != "ssh-manage" || s.Requirement != "biometric" || s.Management == nil || s.Management.Operation != tc.operation {
						t.Fatal("management approval context missing")
					}
					text := s.String()
					serialized, _ := json.Marshal(s)
					for _, secret := range []string{"fixture-hidden-passphrase", "fixture-hidden-pin", base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)))} {
						if strings.Contains(text, secret) || strings.Contains(string(serialized), secret) {
							t.Fatal("secret appeared in approval context")
						}
					}
				case <-time.After(time.Second):
					t.Fatal("no management approval")
				}
				if calls.Load() != int32(i) {
					t.Fatal("management reached upstream before approval")
				}
				release <- struct{}{}
				p, err := protocol.Read(conn)
				if err != nil || !bytes.Equal(p, []byte{6}) {
					t.Fatalf("management result: %v", err)
				}
			}
		})
	}
}

func TestManagementScopesRefuseBeforePrompt(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.Policy = managementPolicy(t,
		policy.ManagementRule{Operation: "remove-key", Approval: "prompt", Fingerprints: []string{sshagent.Fingerprint(testKey(1))}},
		policy.ManagementRule{Operation: "add-provider", Approval: "prompt", Providers: []string{"/allowed/provider.so"}},
	)
	calls := mockUpstream(t, h, func([]byte) []byte { return []byte{6} })
	conn := h.dial()
	defer conn.Close()
	for _, p := range [][]byte{managementPacket(18, testKey(2)), managementPacket(20, []byte("/other/provider.so"), nil), {19}, addFixture(), {22}, {17}} {
		if result := roundTrip(t, conn, p); !bytes.Equal(result, []byte{5}) {
			t.Fatal("unlisted management operation passed")
		}
	}
	if prompts.Load() != 0 || calls.Load() != 0 {
		t.Fatal("unlisted target reached approval or upstream")
	}
}

func TestManagementDenialAndExpiry(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "denial", true: "expiry"}[expiry], func(t *testing.T) {
			h, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
				if expiry {
					<-ctx.Done()
					return nil
				}
				return errors.New("denied")
			}, "", time.Second)
			h.server.ApprovalTimeout = 50 * time.Millisecond
			calls := mockUpstream(t, h, func([]byte) []byte { return []byte{6} })
			conn := h.dial()
			defer conn.Close()
			if result := roundTrip(t, conn, []byte{19}); !bytes.Equal(result, []byte{5}) {
				t.Fatal("failed approval changed upstream")
			}
			if calls.Load() != 0 {
				t.Fatal("failed approval reached upstream")
			}
		})
	}
}

func TestManagementDisconnectAndUpstreamDenial(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	h, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}, "", time.Second)
	calls := mockUpstream(t, h, func([]byte) []byte { return []byte{6} })
	conn := h.dial()
	if err := protocol.Write(conn, []byte{19}); err != nil {
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
		t.Fatal("approval survived disconnect")
	}
	if calls.Load() != 0 {
		t.Fatal("disconnected management reached upstream")
	}
	other, _ := startServer(t, allow, "", time.Second)
	mockUpstream(t, other, func([]byte) []byte { return []byte{5} })
	second := other.dial()
	defer second.Close()
	if result := roundTrip(t, second, []byte{19}); !bytes.Equal(result, []byte{5}) {
		t.Fatal("upstream management denial was ignored")
	}
}

func TestManagementClearsSensitivePacket(t *testing.T) {
	for _, denied := range []bool{false, true} {
		p := managementPacket(22, []byte("fixture-hidden-passphrase"))
		expected := bytes.Clone(p)
		a, b := net.Pipe()
		s := &Server{Policy: policy.AllowAll(), Approve: func(context.Context, approval.Summary) error {
			if denied {
				return errors.New("denied")
			}
			return nil
		}, ApprovalTimeout: time.Second, approvals: make(chan struct{}, 1)}
		called := false
		_, err := s.manage(context.Background(), a, p, connectionInfo{}, func(packet []byte) ([]byte, error) {
			called = true
			if !bytes.Equal(packet, expected) {
				t.Error("secret packet changed before forwarding")
			}
			return []byte{6}, nil
		})
		a.Close()
		b.Close()
		if err != nil || called == denied {
			t.Fatal("management approval flow differs")
		}
		if !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("sensitive packet remained after management")
		}
	}
}

func TestManagementDoesNotResetSigningQuota(t *testing.T) {
	h, _ := startServer(t, allow, "", time.Second)
	h.server.Policy = signingPolicy(t, testKey(1), []string{"raw"}, nil, 1)
	h.server.Policy.SSH.Management = policy.ManagementPolicy{Default: "allow", DefaultApproval: "prompt"}
	mockUpstream(t, h, func(p []byte) []byte {
		if p[0] == 13 {
			return signature([]byte("data"))
		}
		return []byte{6}
	})
	conn := h.dial()
	defer conn.Close()
	if p := roundTrip(t, conn, signPacket(testKey(1), []byte("data"))); p[0] != 14 {
		t.Fatal("initial signature failed")
	}
	for _, packet := range [][]byte{{19}, addFixture()} {
		if p := roundTrip(t, conn, packet); !bytes.Equal(p, []byte{6}) {
			t.Fatal("approved management failed")
		}
	}
	if p := roundTrip(t, conn, signPacket(testKey(1), []byte("data"))); !bytes.Equal(p, []byte{5}) {
		t.Fatal("management reset signing quota")
	}
}

func TestManagementUnpromptedRuleForwards(t *testing.T) {
	h, _ := startServer(t, func(context.Context, approval.Summary) error {
		t.Error("unprompted management asked for approval")
		return nil
	}, "", time.Second)
	h.server.Policy = managementPolicy(t, policy.ManagementRule{Operation: "remove-all-keys", Approval: "none"})
	calls := mockUpstream(t, h, func([]byte) []byte { return []byte{6} })
	conn := h.dial()
	defer conn.Close()
	if result := roundTrip(t, conn, []byte{19}); !bytes.Equal(result, []byte{6}) {
		t.Fatalf("reply %v", result)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d", calls.Load())
	}
}
