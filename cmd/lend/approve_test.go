package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/protocol"
)

func TestHookAdapters(t *testing.T) {
	claude := `{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"rm -rf build","description":"Clean the build"},"cwd":"/work"}`
	claudePre := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/work"}`
	agy := `{"hookEventName":"PreToolUse","toolCall":{"name":"run_command","args":{"CommandLine":"npm test"}},"workspacePaths":["/work"]}`
	pi := `{"agent":"pi","tool":"bash","input":{"command":"git push"},"cwd":"/work"}`
	unavailable := errors.New("dial unix: no such file")
	for _, test := range []struct {
		name, hook, input string
		result            error
		output            string
		code              int
	}{
		{"claude allow", "claude-code", claude, nil, `{"hookSpecificOutput":{"decision":{"behavior":"allow"},"hookEventName":"PermissionRequest"}}`, 0},
		{"claude deny", "claude-code", claude, client.ErrDenied, `{"hookSpecificOutput":{"decision":{"behavior":"deny","message":"Denied in lend on the laptop."},"hookEventName":"PermissionRequest"}}`, 0},
		{"claude unavailable", "claude-code", claude, unavailable, ``, 0},
		{"claude pre allow", "claude-code", claudePre, nil, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Approved in lend on the laptop."}}`, 0},
		{"codex allow", "codex", claude, nil, `{"hookSpecificOutput":{"decision":{"behavior":"allow"},"hookEventName":"PermissionRequest"}}`, 0},
		{"codex pre allow", "codex", claudePre, nil, ``, 0},
		{"codex pre deny", "codex", claudePre, client.ErrDenied, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Denied in lend on the laptop."}}`, 0},
		{"agy allow", "agy", agy, nil, `{"decision":"auto_approve","reason":"Approved in lend on the laptop."}`, 0},
		{"agy deny", "agy", agy, client.ErrDenied, `{"decision":"deny","reason":"Denied in lend on the laptop."}`, 0},
		{"agy unavailable", "agy", agy, unavailable, `{"decision":"ask","reason":"lend could not decide: dial unix: no such file"}`, 0},
		{"pi allow", "pi", pi, nil, ``, 0},
		{"pi deny", "pi", pi, client.ErrDenied, ``, 1},
		{"pi unavailable", "pi", pi, unavailable, ``, 125},
		{"unsupported event", "claude-code", `{"hook_event_name":"Stop"}`, nil, ``, 0},
		{"claude malformed", "claude-code", `{"hook_event_name":`, nil, ``, 2},
		{"claude pre missing tool", "claude-code", `{"hook_event_name":"PreToolUse","tool_input":{}}`, nil, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"malformed hook input: missing tool_name"}}`, 0},
		{"claude pre long command", "claude-code", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + strings.Repeat("x", maxCommandDisplay+1) + `"}}`, nil, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"command is 16385 bytes, too long to show in full for approval"}}`, 0},
		{"agy malformed", "agy", `[]`, nil, `{"decision":"deny","reason":"malformed hook input: input is not a JSON hook event"}`, 0},
		{"pi oversized", "pi", strings.Repeat(" ", maxHookInput+1), nil, ``, 1},
		{"claude empty object", "claude-code", `{}`, nil, ``, 2},
		{"claude broken permission request", "claude-code", `{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":`, nil, `{"hookSpecificOutput":{"decision":{"behavior":"deny","message":"malformed hook input: input is not a JSON hook event"},"hookEventName":"PermissionRequest"}}`, 0},
		{"claude nested event before real event", "claude-code", `{"tool_input":{"hook_event_name":"PreToolUse","x":["hook_event_name"]},"hook_event_name":"PermissionRequest","tool_name":"Bash",`, nil, `{"hookSpecificOutput":{"decision":{"behavior":"deny","message":"malformed hook input: input is not a JSON hook event"},"hookEventName":"PermissionRequest"}}`, 0},
		{"claude oversized permission request", "claude-code", `{"hook_event_name":"PermissionRequest","tool_input":{"content":"` + strings.Repeat("x", maxHookInput) + `"}}`, nil, `{"hookSpecificOutput":{"decision":{"behavior":"deny","message":"hook input exceeds 64 MiB"},"hookEventName":"PermissionRequest"}}`, 0},
		{"json allow", "json", `{"tool":"deploy","input":{"service":"api"}}`, nil, ``, 0},
		{"json unknown field", "json", `{"toolName":"bash"}`, nil, ``, 1},
		{"claude-compatible deny", "claude-compatible", claude, client.ErrDenied, `{"hookSpecificOutput":{"decision":{"behavior":"deny","message":"Denied in lend on the laptop."},"hookEventName":"PermissionRequest"}}`, 0},
		{"codex null", "codex", `null`, nil, ``, 2},
		{"claude pre long path", "claude-code", `{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"` + strings.Repeat("./", protocol.MaxApprovalDetails) + `x"}}`, nil, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"tool input is too large to show for approval (65565 bytes)"}}`, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code, err := runHook(context.Background(), hookAdapters[test.hook], test.hook, func(protocol.ApprovalRequest) error { return test.result }, strings.NewReader(test.input), &stdout, &stderr)
			if err != nil || code != test.code || strings.TrimSpace(stdout.String()) != test.output {
				t.Fatalf("code=%d err=%v stdout=%s stderr=%s", code, err, stdout.String(), stderr.String())
			}
		})
	}
}

func TestHookRequestDescribesTheToolCall(t *testing.T) {
	var got protocol.ApprovalRequest
	input := `{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"echo \"<a>\" && ls","description":"List files","timeout":120000},"cwd":"/work"}`
	if _, err := runHook(context.Background(), hookAdapters["claude-code"], "claude-code", func(r protocol.ApprovalRequest) error { got = r; return nil }, strings.NewReader(input), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	want := "Working directory: /work\n\nCommand:\necho \"<a>\" && ls\n\nInput:\n{\n  \"timeout\": 120000\n}"
	if got.Topic != "claude-code" || got.Title != "Claude Code wants to use Bash" || got.Reason != "List files" || got.Details != want {
		t.Fatalf("request=%+v", got)
	}
	if got.Caller == nil || got.Caller.ClientName != "claude-code" || got.Caller.Tool != "Bash" {
		t.Fatalf("caller=%+v", got.Caller)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestHookDetailsKeepShortFieldsBesideLargeContent(t *testing.T) {
	var got protocol.ApprovalRequest
	input := `{"tool":"write","input":{"path":"/work/` + strings.Repeat("d/", 1500) + `zz.txt","content":"` + strings.Repeat("é\\n", protocol.MaxApprovalDetails/4) + `"}}`
	if _, err := runHook(context.Background(), hookAdapters["pi"], "pi", func(r protocol.ApprovalRequest) error { got = r; return nil }, strings.NewReader(input), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil || !strings.Contains(got.Details, `d/zz.txt"`) || !strings.Contains(got.Details, "more bytes not shown]") {
		t.Fatalf("details=%.300q err=%v", got.Details, err)
	}
}

func TestHookInputWithNULStillReachesTheLaptop(t *testing.T) {
	sent := false
	input := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","description":"\u0000"}}`
	var stdout bytes.Buffer
	if _, err := runHook(context.Background(), hookAdapters["codex"], "codex", func(protocol.ApprovalRequest) error { sent = true; return client.ErrDenied }, strings.NewReader(input), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !sent || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("sent=%t stdout=%s", sent, stdout.String())
	}
}

func TestGenericHookTitles(t *testing.T) {
	for _, test := range []struct{ hook, input, title, client string }{
		{"json", `{"agent":"my-agent","tool":"deploy"}`, "my-agent wants to use deploy", "my-agent"},
		{"json", `{"tool":"deploy"}`, "ops wants to use deploy", "ops"},
		{"claude-compatible", `{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{}}`, "ops wants to use shell", "ops"},
	} {
		var got protocol.ApprovalRequest
		if _, err := runHook(context.Background(), hookAdapters[test.hook], "ops", func(r protocol.ApprovalRequest) error { got = r; return nil }, strings.NewReader(test.input), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if got.Topic != "ops" || got.Title != test.title || got.Caller.ClientName != test.client {
			t.Fatalf("%s: request=%+v caller=%+v", test.hook, got, got.Caller)
		}
	}
}

func TestApproveCommandArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--title", "x"},
		{"--topic", "t"},
		{"--hook", "copilot"},
		{"--hook", "codex", "--title", "x"},
		{"--hook", "json"},
		{"--hook", "claude-compatible"},
		{"--topic", "t", "--title", "x", "--details", "a", "--details-file", "b"},
		{"--topic", "t", "--title", "x", "extra"},
	} {
		if code, err := approveCommand(context.Background(), append([]string{"--socket", "/nonexistent"}, args...), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 2 || err == nil {
			t.Fatalf("args=%v code=%d err=%v", args, code, err)
		}
	}
}
