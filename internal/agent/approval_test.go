package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/control"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
)

func TestApprovalRequests(t *testing.T) {
	var seen []approval.Summary
	allow := true
	h, _ := startServer(t, func(_ context.Context, s approval.Summary) error {
		seen = append(seen, s)
		if !allow {
			return errors.New("denied")
		}
		return nil
	}, "", time.Second)
	p, err := policy.Parse([]byte(`{"approvals":{"topics":[{"name":"claude-code","approval":"biometric:inline"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	h.server.Policy = p
	request := protocol.ApprovalRequest{Topic: "claude-code", Title: "Claude Code wants to use Bash", Details: "Command:\nrm -rf build", Reason: "clean the build"}
	if err := client.ApproveConn(context.Background(), h.dial(), request); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Kind != "approval" || seen[0].Requirement != "biometric:inline" || seen[0].Title != request.Title || seen[0].Details != request.Details {
		t.Fatalf("summary=%+v", seen)
	}
	allow = false
	if err := client.ApproveConn(context.Background(), h.dial(), request); !errors.Is(err, client.ErrDenied) {
		t.Fatalf("denied approval returned %v", err)
	}
	request.Topic = "deploy"
	if err := client.ApproveConn(context.Background(), h.dial(), request); !errors.Is(err, client.ErrDenied) {
		t.Fatalf("unlisted topic returned %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("unlisted topic reached the prompt: %d prompts", len(seen))
	}
	history := h.server.Activity.Snapshot(true).History
	states := []string{}
	for _, entry := range history {
		if entry.Kind == "approval" {
			if entry.Topic == "" || entry.Info != nil {
				t.Fatalf("history entry=%+v", entry)
			}
			states = append(states, entry.State)
		}
	}
	if strings.Join(states, ",") != "approved,denied,denied" {
		t.Fatalf("states=%v", states)
	}
}

func TestApprovalRequestCanContinueOnConnection(t *testing.T) {
	h, _ := startServer(t, func(context.Context, approval.Summary) error { return nil }, "", time.Second)
	conn := h.dial()
	defer conn.Close()
	for range 2 {
		packet, err := protocol.EncodeApproval(protocol.ApprovalRequest{Topic: "t", Title: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if err := protocol.Write(conn, packet); err != nil {
			t.Fatal(err)
		}
		reply, err := protocol.Read(conn)
		if err != nil || len(reply) != 1 || reply[0] != protocol.AgentSuccess {
			t.Fatalf("reply=%v err=%v", reply, err)
		}
	}
}

func TestRevokedApprovalIsARefusal(t *testing.T) {
	prompted := make(chan struct{})
	h, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		close(prompted)
		<-ctx.Done()
		return ctx.Err()
	}, "", 5*time.Second)
	h.server.ApprovalTimeout = 5 * time.Second
	done := make(chan error, 1)
	go func() {
		done <- client.ApproveConn(context.Background(), h.dial(), protocol.ApprovalRequest{Topic: "t", Title: "x"})
	}()
	<-prompted
	h.server.Control(control.Request{Action: "pause"})
	if err := <-done; !errors.Is(err, client.ErrDenied) {
		t.Fatalf("paused approval returned %v", err)
	}
}
