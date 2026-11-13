package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/protocol"
)

type session struct {
	conn   net.Conn
	encode *json.Encoder
	decode *json.Decoder
	t      *testing.T
}

func connect(t *testing.T, runner Runner) *session {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	s := &Server{Run: runner}
	go func() { done <- s.Serve(ctx, server, server) }()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() {
		cancel()
		client.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("MCP server did not stop")
		}
	})
	return &session{conn: client, encode: json.NewEncoder(client), decode: json.NewDecoder(client), t: t}
}

func (s *session) send(value any) {
	s.t.Helper()
	if err := s.encode.Encode(value); err != nil {
		s.t.Fatal(err)
	}
}

func (s *session) read() response {
	s.t.Helper()
	var result response
	if err := s.decode.Decode(&result); err != nil {
		s.t.Fatal(err)
	}
	return result
}

func (s *session) init() {
	s.initClient("test", "1")
}

func (s *session) initClient(name, clientVersion string) {
	s.t.Helper()
	s.send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": name, "version": clientVersion}}})
	r := s.read()
	if r.Error != nil || r.Result.(map[string]any)["protocolVersion"] != version {
		s.t.Fatalf("initialize: %+v", r)
	}
	s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

func TestMCPCallerContextIsPerSessionAndCall(t *testing.T) {
	for _, name := range []string{"first-client", "second-client"} {
		t.Run(name, func(t *testing.T) {
			seen := make(chan protocol.Caller, 2)
			s := connect(t, func(_ context.Context, r protocol.Request, _ io.Reader, _, _ io.Writer) (int, error) {
				seen <- *r.Caller
				return 0, nil
			})
			s.initClient(name, "2")
			for _, id := range []string{"first-call", "second-call"} {
				s.send(call(id, map[string]any{"args": []string{"true"}, "reason": "inspect"}))
				if r := s.read(); r.Error != nil {
					t.Fatal(r.Error)
				}
				c := <-seen
				if c.ClientName != name || c.ClientVersion != "2" || c.RequestID != id || c.Source != "mcp" || c.Tool != "run_local_command" {
					t.Fatal("MCP caller metadata crossed sessions or calls")
				}
			}
		})
	}
}

func TestMCPRejectsOversizedClientMetadata(t *testing.T) {
	s := connect(t, func(context.Context, protocol.Request, io.Reader, io.Writer, io.Writer) (int, error) {
		t.Error("tool ran")
		return 0, nil
	})
	s.send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": version, "clientInfo": map[string]any{"name": strings.Repeat("x", 257), "version": "1"}}})
	if r := s.read(); r.Error == nil || r.Error.Code != -32602 {
		t.Fatal("oversized client name accepted")
	}
	s.init()
}

func call(id any, args map[string]any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "run_local_command", "arguments": args}}
}

func TestMCPToolRunsWithReasonAndInput(t *testing.T) {
	s := connect(t, func(_ context.Context, r protocol.Request, input io.Reader, out, stderr io.Writer) (int, error) {
		if r.Reason != "inspect a pull request" || strings.Join(r.Args, " ") != "gh pr view 123" {
			t.Errorf("request: %+v", r)
		}
		if r.Caller == nil || r.Caller.Source != "mcp" || r.Caller.ClientName != "test" || r.Caller.ClientVersion != "1" || r.Caller.Tool != "run_local_command" || r.Caller.RequestID != "3" || r.Caller.PID <= 0 {
			t.Error("MCP caller context missing")
		}
		data, err := io.ReadAll(input)
		if err != nil || string(data) != "input" {
			t.Errorf("stdin: %q %v", data, err)
		}
		out.Write([]byte("result"))
		stderr.Write([]byte("diagnostic"))
		return 7, nil
	})
	s.init()
	s.send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	r := s.read()
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	tools := r.Result.(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "run_local_command" {
		t.Fatalf("tools: %v", tools)
	}
	s.send(call(3, map[string]any{"args": []string{"gh", "pr", "view", "123"}, "reason": "inspect a pull request", "stdin": "input"}))
	r = s.read()
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	result := r.Result.(map[string]any)
	data := result["structuredContent"].(map[string]any)
	if result["isError"] != true || data["exit_code"] != float64(7) || data["stdout"].(map[string]any)["text"] != "result" || data["stderr"].(map[string]any)["text"] != "diagnostic" {
		t.Fatalf("result: %v", result)
	}
}

func TestMCPCancellationRemainsResponsive(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	s := connect(t, func(ctx context.Context, _ protocol.Request, _ io.Reader, _, _ io.Writer) (int, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return 125, ctx.Err()
	})
	s.init()
	s.send(call("run", map[string]any{"args": []string{"gh", "pr", "view"}, "reason": "inspect"}))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("tool did not start")
	}
	s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": "run"}})
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("tool was not cancelled")
	}
	s.send(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "ping"})
	if r := s.read(); r.Error != nil || string(r.ID) != "4" {
		t.Fatalf("ping: %+v", r)
	}
}

func TestMCPRejectsInvalidArgumentsBeforeRunning(t *testing.T) {
	s := connect(t, func(context.Context, protocol.Request, io.Reader, io.Writer, io.Writer) (int, error) {
		t.Error("invalid tool ran")
		return 0, nil
	})
	s.send(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
	if r := s.read(); r.Error == nil {
		t.Fatal("tool discovery allowed before initialization")
	}
	s.init()
	for _, args := range []map[string]any{
		{"args": []string{"gh"}},
		{"args": []string{"gh"}, "reason": "  "},
		{"args": []string{"gh"}, "reason": "inspect", "approval": "prompt"},
		{"args": []string{"gh"}, "reason": "inspect", "caller": map[string]any{"source": "mcp", "client_name": "fake"}},
		{"args": []string{}, "reason": "inspect"},
		{"args": []string{"gh"}, "reason": "inspect", "stdin": strings.Repeat("x", 65537)},
	} {
		s.send(call(2, args))
		if r := s.read(); r.Error == nil || r.Error.Code != -32602 {
			t.Fatalf("invalid tool arguments accepted: %+v", r)
		}
	}
}

func TestMCPEOFClosesActiveCall(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	s := connect(t, func(ctx context.Context, _ protocol.Request, _ io.Reader, _, _ io.Writer) (int, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return 125, ctx.Err()
	})
	s.init()
	s.send(call(2, map[string]any{"args": []string{"gh"}, "reason": "inspect"}))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("tool did not start")
	}
	s.conn.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("tool survived session EOF")
	}
}

func TestMCPBoundsOutputAndPreservesBinary(t *testing.T) {
	s := &Server{Run: func(_ context.Context, _ protocol.Request, _ io.Reader, out, stderr io.Writer) (int, error) {
		out.Write(bytes.Repeat([]byte{'x'}, maxOutput+100))
		stderr.Write([]byte{0xff, 0x00})
		return 0, nil
	}}
	result := s.call(context.Background(), protocol.Request{Args: []string{"tool"}}, "")
	data := result["structuredContent"].(map[string]any)
	out := data["stdout"].(map[string]any)
	if out["truncated"] != true || len(out["text"].(string)) != maxOutput {
		t.Fatalf("output limit: %v", out["truncated"])
	}
	if data["stderr"].(map[string]any)["base64"] != "/wA=" {
		t.Fatal("binary output changed")
	}
}

func TestRequestIDKeys(t *testing.T) {
	if idKey(json.RawMessage(`"run"`)) != idKey(json.RawMessage(`"\u0072un"`)) {
		t.Fatal("equivalent IDs have different keys")
	}
	for _, id := range []string{"null", "true", "[]", "1.5"} {
		if validID(json.RawMessage(id)) {
			t.Fatalf("invalid ID %s", id)
		}
	}
}

type blockingInput struct{ release chan struct{} }

func (b blockingInput) Read([]byte) (int, error) { <-b.release; return 0, io.EOF }
func (blockingInput) Close() error               { return nil }

func TestCancellationDoesNotWaitForBlockedStdin(t *testing.T) {
	input := blockingInput{release: make(chan struct{})}
	defer close(input.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	s := &Server{Run: func(context.Context, protocol.Request, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }}
	go func() { done <- s.Serve(ctx, input, io.Discard) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for blocked stdin")
	}
}
