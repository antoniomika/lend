package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func TestSSHCallerHintsOnlyIncludeAcceptedBindings(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "refused", true: "accepted"}[accepted], func(t *testing.T) {
			var summary approval.Summary
			h, _ := startServer(t, func(_ context.Context, s approval.Summary) error { summary = s; return nil }, "", time.Second)
			mockUpstream(t, h, func(p []byte) []byte {
				if p[0] == 27 {
					if accepted {
						return []byte{6}
					}
					return []byte{5}
				}
				return signature([]byte("data"))
			})
			conn := h.dial()
			defer conn.Close()
			roundTrip(t, conn, sessionBinding(testKey(2)))
			if p := roundTrip(t, conn, signPacket(testKey(1), []byte("data"))); p[0] != 14 {
				t.Fatal("signature failed")
			}
			if accepted {
				if len(summary.Bindings) != 1 || summary.Bindings[0].Fingerprint != sshagent.Fingerprint(testKey(2)) || !summary.Bindings[0].Forwarding {
					t.Fatal("accepted binding hint missing")
				}
			} else if len(summary.Bindings) != 0 {
				t.Fatal("refused binding displayed as accepted")
			}
			if summary.Caller != nil || summary.Peer != nil {
				t.Fatal("ordinary SSH or in-memory peer fabricated caller details")
			}
			other := h.dial()
			defer other.Close()
			if p := roundTrip(t, other, signPacket(testKey(1), []byte("data"))); p[0] != 14 || len(summary.Bindings) != 0 {
				t.Fatal("SSH session hints leaked across connections")
			}
		})
	}
}

func TestConnectionHintsAreBoundedAndCopied(t *testing.T) {
	var info connectionInfo
	for i := 0; i < 10; i++ {
		info.bind(sshagent.Binding{Fingerprint: "SHA256:fixture", Forwarding: true})
	}
	s := info.summary(approval.Summary{})
	if len(s.Bindings) != 8 || s.OmittedBindings != 2 {
		t.Fatal("binding hint count is unbounded")
	}
	info.bindings[0].Fingerprint = "changed"
	if s.Bindings[0].Fingerprint != "SHA256:fixture" {
		t.Fatal("approval details changed after capture")
	}
}

func TestCallerCannotSupplyObservedPeerOrChangePolicy(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	h.server.Policy = &policy.Policy{Default: "deny"}
	conn := h.dial()
	defer conn.Close()
	request := protocol.Request{Args: []string{"true"}, Caller: &protocol.Caller{Source: "mcp", ClientName: "trusted-looking", Host: "laptop"}}
	data, _ := json.Marshal(request)
	p := roundTrip(t, conn, protocol.ExtensionPacket(27, protocol.Extension, data))
	if !bytes.Equal(p, []byte{28}) || prompts.Load() != 0 {
		t.Fatal("reported caller changed command policy")
	}
	h.server.Policy = policy.AllowAll()
	for _, payload := range []string{
		`{"args":["true"],"caller":{"source":"cli","verified":true}}`,
		`{"args":["true"],"peer":{"PID":1,"UID":0}}`,
		`{"args":["true"],"caller":{"source":"cli","host":"bad\u0000host"}}`,
	} {
		other := h.dial()
		p := roundTrip(t, other, protocol.ExtensionPacket(27, protocol.Extension, []byte(payload)))
		other.Close()
		if !bytes.Equal(p, []byte{28}) {
			t.Fatal("invalid caller metadata accepted")
		}
	}
	if prompts.Load() != 0 {
		t.Fatal("invalid caller metadata reached approval")
	}
}

func TestCommandCallerRetainsSSHBindingContext(t *testing.T) {
	var summary approval.Summary
	h, _ := startServer(t, func(_ context.Context, s approval.Summary) error { summary = s; return nil }, "", time.Second)
	mockUpstream(t, h, func([]byte) []byte { return []byte{6} })
	conn := h.dial()
	defer conn.Close()
	if p := roundTrip(t, conn, sessionBinding(testKey(2))); !bytes.Equal(p, []byte{6}) {
		t.Fatal("binding refused")
	}
	request := protocol.Request{Args: []string{"printf", "hello"}, Caller: &protocol.Caller{Source: "mcp", ClientName: "example-agent", Tool: "run_local_command"}}
	var out bytes.Buffer
	code, err := client.RunRequestConn(context.Background(), conn, request, strings.NewReader(""), &out, io.Discard)
	if err != nil || code != 0 || out.String() != "hello" {
		t.Fatalf("%d %v", code, err)
	}
	if summary.Caller == nil || summary.Caller.ClientName != "example-agent" || len(summary.Bindings) != 1 {
		t.Fatal("command lost caller or connection context")
	}
}
