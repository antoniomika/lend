package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/protocol"
)

// A hook adapter turns an agent's hook input into an approval request and the verdict back into the
// output that agent expects.
type hookAdapter struct {
	name    string
	display string
	parse   func([]byte) (hookCall, error)
	respond func(call hookCall, v verdict, message string) (output []byte, code int)
}

type verdict int

const (
	// undecided leaves the agent's own permission flow in charge. Only an unreachable laptop or a
	// hook event the adapter does not handle produces it; everything else fails closed.
	undecided verdict = iota
	approved
	denied
)

var errNotHookJSON = errors.New("input is not a JSON hook event")

// errUnsupportedEvent marks well-formed input for an event the adapter does not gate.
var errUnsupportedEvent = errors.New("unsupported hook event")

const (
	// Large enough to parse a write of any file an agent would reasonably send, so the event is known.
	maxHookInput      = 64 * 1024 * 1024
	maxCommandDisplay = 16 * 1024
	maxFieldDisplay   = 2048
)

type hookCall struct {
	event     string
	agent     string
	tool      string
	input     json.RawMessage
	directory string
}

var hookAdapters = map[string]hookAdapter{
	"claude-code": {name: "claude-code", display: "Claude Code", parse: parseSnakeHook, respond: respondPermissionHook(true)},
	"codex":       {name: "codex", display: "Codex", parse: parseSnakeHook, respond: respondPermissionHook(false)},
	"agy":         {name: "agy", display: "Antigravity", parse: parseAgyHook, respond: respondAgyHook},
	"pi":          {name: "pi", display: "pi", parse: parseJSONHook, respond: respondExitCode},
	// Generic formats have no agent of their own, so they need --topic.
	"claude-compatible": {parse: parseSnakeHook, respond: respondPermissionHook(true)},
	"json":              {parse: parseJSONHook, respond: respondExitCode},
}

const hookNames = "claude-code, codex, agy, pi, claude-compatible, or json"

func approveCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", os.Getenv("SSH_AUTH_SOCK"), "forwarded agent socket")
	topic := fs.String("topic", "", "approval topic matched against the laptop policy (hooks default to the agent name)")
	title := fs.String("title", "", "one-line summary shown in the approval dialog")
	details := fs.String("details", "", "longer text shown in the approval dialog")
	detailsFile := fs.String("details-file", "", "read the details from a file, or - for stdin")
	reason := fs.String("reason", "", "why approval is needed")
	hook := fs.String("hook", "", "read a hook event from stdin: "+hookNames)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if fs.NArg() != 0 {
		return 2, errors.New("approve takes no positional arguments")
	}
	if *hook != "" {
		adapter, ok := hookAdapters[*hook]
		if !ok {
			return 2, fmt.Errorf("unknown hook %q; use %s", *hook, hookNames)
		}
		if *title != "" || *details != "" || *detailsFile != "" || *reason != "" {
			return 2, errors.New("--hook builds the request from the hook input; drop --title, --details, --details-file, and --reason")
		}
		if *topic == "" {
			*topic = adapter.name
		}
		if *topic == "" {
			return 2, fmt.Errorf("--hook %s requires --topic", *hook)
		}
		send := func(request protocol.ApprovalRequest) error {
			if *socket == "" {
				return errors.New("SSH_AUTH_SOCK is unset; pass --socket")
			}
			return client.Approve(ctx, *socket, request)
		}
		return runHook(ctx, adapter, *topic, send, stdin, stdout, stderr)
	}
	if *topic == "" || *title == "" {
		return 2, errors.New("approve requires --topic and --title, or --hook")
	}
	if *details != "" && *detailsFile != "" {
		return 2, errors.New("choose one of --details or --details-file")
	}
	if *detailsFile != "" {
		var data []byte
		var err error
		if *detailsFile == "-" {
			data, err = io.ReadAll(io.LimitReader(stdin, protocol.MaxApprovalDetails+1))
		} else {
			data, err = readLimited(*detailsFile, protocol.MaxApprovalDetails+1)
		}
		if err != nil {
			return 2, err
		}
		if len(data) > protocol.MaxApprovalDetails {
			return 2, fmt.Errorf("details exceed %d bytes", protocol.MaxApprovalDetails)
		}
		*details = string(data)
	}
	if *socket == "" {
		return 2, errors.New("SSH_AUTH_SOCK is unset; use --socket")
	}
	who := caller.Capture(ctx, "cli")
	err := client.Approve(ctx, *socket, protocol.ApprovalRequest{Topic: *topic, Title: *title, Details: *details, Reason: *reason, Caller: &who})
	if errors.Is(err, client.ErrDenied) {
		return 1, err
	}
	if err != nil {
		return 125, err
	}
	return 0, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

func runHook(ctx context.Context, adapter hookAdapter, topic string, send func(protocol.ApprovalRequest) error, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	finish := func(call hookCall, v verdict, message string) (int, error) {
		if v != approved {
			fmt.Fprintf(stderr, "lend: %s\n", message)
		}
		output, code := adapter.respond(call, v, message)
		if len(output) > 0 {
			if _, err := stdout.Write(append(output, '\n')); err != nil {
				return 1, err
			}
		}
		return code, nil
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxHookInput+1))
	if err != nil {
		return finish(hookCall{}, denied, "could not read hook input")
	}
	if len(data) > maxHookInput {
		return finish(hookCall{event: sniffEvent(data)}, denied, "hook input exceeds 64 MiB")
	}
	call, err := adapter.parse(data)
	if err != nil && call.event == "" {
		call.event = sniffEvent(data)
	}
	if errors.Is(err, errUnsupportedEvent) {
		return finish(call, undecided, err.Error())
	}
	if err != nil {
		return finish(call, denied, "malformed hook input: "+err.Error())
	}
	details, reason, err := describeTool(call)
	if err != nil {
		return finish(call, denied, err.Error())
	}
	display := adapter.display
	if display == "" {
		display = topic
		if call.agent != "" {
			display = truncate(displayable(call.agent), 64)
		}
	}
	who := caller.Capture(ctx, "client")
	who.ClientName = adapter.name
	if who.ClientName == "" {
		who.ClientName = truncate(display, 256)
	}
	who.Tool = truncate(displayable(call.tool), 128)
	request := protocol.ApprovalRequest{Topic: topic, Title: truncate(display+" wants to use "+displayable(call.tool), protocol.MaxApprovalTitle), Details: details, Reason: truncate(reason, 2048), Caller: &who}
	if err := request.Validate(); err != nil {
		return finish(call, denied, "cannot build approval request: "+err.Error())
	}
	err = send(request)
	if errors.Is(err, client.ErrDenied) {
		return finish(call, denied, "Denied in lend on the laptop.")
	}
	if err != nil {
		return finish(call, undecided, err.Error())
	}
	return finish(call, approved, "Approved in lend on the laptop.")
}

// sniffEvent reads top-level keys of input that cannot be fully parsed, so a denial still uses the
// format its event requires. It stops at the first malformed token.
func sniffEvent(data []byte) string {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ""
	}
	for {
		key, err := decoder.Token()
		if err != nil {
			return ""
		}
		name, ok := key.(string)
		if !ok {
			return ""
		}
		value, err := decoder.Token()
		if err != nil {
			return ""
		}
		if name == "hook_event_name" {
			if event, ok := value.(string); ok && (event == "PermissionRequest" || event == "PreToolUse") {
				return event
			}
			return ""
		}
		if value == json.Delim('{') || value == json.Delim('[') {
			for depth := 1; depth > 0; {
				token, err := decoder.Token()
				if err != nil {
					return ""
				}
				switch token {
				case json.Delim('{'), json.Delim('['):
					depth++
				case json.Delim('}'), json.Delim(']'):
					depth--
				}
			}
		}
	}
}

// describeTool shows the command in full, then the rest of the input as JSON with long strings
// shortened. A command too long to show is refused so approval never covers text the dialog hid.
func describeTool(call hookCall) (string, string, error) {
	var b strings.Builder
	if call.directory != "" {
		fmt.Fprintf(&b, "Working directory: %s\n\n", displayable(call.directory))
	}
	var input any
	decoder := json.NewDecoder(bytes.NewReader(call.input))
	decoder.UseNumber()
	if len(call.input) > 0 && decoder.Decode(&input) != nil {
		return "", "", errors.New("tool input is not valid JSON")
	}
	reason := ""
	if fields, ok := input.(map[string]any); ok {
		if description, ok := fields["description"].(string); ok {
			reason = displayable(description)
			delete(fields, "description")
		}
		for _, key := range []string{"command", "CommandLine", "cmd"} {
			if command, ok := fields[key].(string); ok {
				if len(command) > maxCommandDisplay {
					return "", "", fmt.Errorf("command is %d bytes, too long to show in full for approval", len(command))
				}
				fmt.Fprintf(&b, "Command:\n%s\n\n", displayable(command))
				delete(fields, key)
				break
			}
		}
		if len(fields) == 0 {
			input = nil
		}
	}
	if input != nil {
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(shorten(input)); err != nil {
			return "", "", err
		}
		b.WriteString("Input:\n")
		b.Write(buf.Bytes())
	}
	details := strings.TrimRight(b.String(), "\n")
	if len(details) > protocol.MaxApprovalDetails {
		return "", "", fmt.Errorf("tool input is too large to show for approval (%d bytes)", len(details))
	}
	return details, reason, nil
}

// shorten cuts long multi-line strings, such as file contents and patches, and says how much it
// left out. Single-line values such as paths and URLs are always shown in full.
func shorten(value any) any {
	switch v := value.(type) {
	case string:
		if len(v) <= maxFieldDisplay || !strings.Contains(v, "\n") {
			return displayable(v)
		}
		return displayable(truncate(v, maxFieldDisplay)) + fmt.Sprintf(" [%d more bytes not shown]", len(v)-len(truncate(v, maxFieldDisplay)))
	case map[string]any:
		for key, item := range v {
			v[key] = shorten(item)
		}
	case []any:
		for i, item := range v {
			v[i] = shorten(item)
		}
	}
	return value
}

// displayable keeps text valid for the approval request; the dialog escapes the remaining controls.
func displayable(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", `\x00`)
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func parseSnakeHook(data []byte) (hookCall, error) {
	var input struct {
		Event     string          `json:"hook_event_name"`
		Tool      string          `json:"tool_name"`
		Input     json.RawMessage `json:"tool_input"`
		Directory string          `json:"cwd"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		return hookCall{}, errNotHookJSON
	}
	call := hookCall{event: input.Event, tool: input.Tool, input: input.Input, directory: input.Directory}
	if strings.TrimSpace(call.event) == "" {
		return call, errors.New("missing hook_event_name")
	}
	if call.event != "PermissionRequest" && call.event != "PreToolUse" {
		return call, fmt.Errorf("%w %q; use PermissionRequest or PreToolUse", errUnsupportedEvent, call.event)
	}
	if call.tool == "" {
		return call, errors.New("missing tool_name")
	}
	return call, nil
}

// respondPermissionHook writes the Claude Code and Codex hook decision formats. Codex does not accept
// an allow decision from PreToolUse, so approval there produces no output and the call proceeds.
// Input too malformed to name its event is denied with exit status 2, which both agents treat as a block.
func respondPermissionHook(preToolAllow bool) func(hookCall, verdict, string) ([]byte, int) {
	return func(call hookCall, v verdict, message string) ([]byte, int) {
		if v == undecided {
			return nil, 0
		}
		var specific map[string]any
		switch call.event {
		case "PermissionRequest":
			decision := map[string]any{"behavior": "allow"}
			if v == denied {
				decision = map[string]any{"behavior": "deny", "message": message}
			}
			specific = map[string]any{"hookEventName": call.event, "decision": decision}
		case "PreToolUse":
			if v == approved && !preToolAllow {
				return nil, 0
			}
			specific = map[string]any{"hookEventName": call.event, "permissionDecision": "allow", "permissionDecisionReason": message}
			if v == denied {
				specific["permissionDecision"] = "deny"
			}
		default:
			return nil, 2
		}
		output, _ := json.Marshal(map[string]any{"hookSpecificOutput": specific})
		return output, 0
	}
}

func parseAgyHook(data []byte) (hookCall, error) {
	var input struct {
		Event    string `json:"hookEventName"`
		ToolCall struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		} `json:"toolCall"`
		Directory  string   `json:"cwd"`
		Workspaces []string `json:"workspacePaths"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		return hookCall{}, errNotHookJSON
	}
	call := hookCall{event: "PreToolUse", tool: input.ToolCall.Name, input: input.ToolCall.Args, directory: input.Directory}
	if call.directory == "" && len(input.Workspaces) > 0 {
		call.directory = input.Workspaces[0]
	}
	if input.Event != "" && input.Event != "PreToolUse" {
		return call, fmt.Errorf("%w %q; use PreToolUse", errUnsupportedEvent, input.Event)
	}
	if call.tool == "" {
		return call, errors.New("missing toolCall.name")
	}
	return call, nil
}

// agy treats empty output as allow and an empty object as deny, so every path writes a decision.
func respondAgyHook(_ hookCall, v verdict, message string) ([]byte, int) {
	decision := map[string]string{"decision": "deny", "reason": message}
	switch v {
	case approved:
		decision["decision"] = "auto_approve"
	case undecided:
		decision = map[string]string{"decision": "ask", "reason": "lend could not decide: " + message}
	}
	output, _ := json.Marshal(decision)
	return output, 0
}

// parseJSONHook reads lend's own hook format, which any agent can produce with a small shim.
func parseJSONHook(data []byte) (hookCall, error) {
	var input struct {
		Agent     string          `json:"agent"`
		Tool      string          `json:"tool"`
		Input     json.RawMessage `json:"input"`
		Directory string          `json:"cwd"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return hookCall{}, errNotHookJSON
	}
	call := hookCall{event: "json", agent: input.Agent, tool: input.Tool, input: input.Input, directory: input.Directory}
	if call.tool == "" {
		return call, errors.New("missing tool")
	}
	return call, nil
}

// respondExitCode reports the verdict as 0 approved, 1 denied, or 125 undecided.
func respondExitCode(_ hookCall, v verdict, _ string) ([]byte, int) {
	switch v {
	case approved:
		return nil, 0
	case denied:
		return nil, 1
	}
	return nil, 125
}
