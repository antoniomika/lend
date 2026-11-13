package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/protocol"
)

const version = "2025-11-25"
const maxOutput = 64 * 1024

type Runner func(context.Context, protocol.Request, io.Reader, io.Writer, io.Writer) (int, error)

type Server struct{ Run Runner }

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolArgs struct {
	Args   []string `json:"args"`
	Reason string   `json:"reason"`
	Stdin  string   `json:"stdin,omitempty"`
}

func tool() map[string]any {
	return map[string]any{
		"name":        "run_local_command",
		"description": "Request a command on the user's laptop through the forwarded agent. Explain why access is needed. The laptop enforces its command policy and approval requirements. Output can contain secrets.",
		"inputSchema": map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"args", "reason"},
			"properties": map[string]any{
				"args":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": 256, "description": "Executable and arguments, passed directly without shell expansion."},
				"reason": map[string]any{"type": "string", "minLength": 1, "maxLength": 2048, "description": "Why this command is needed. Displayed in the laptop approval prompt."},
				"stdin":  map[string]any{"type": "string", "maxLength": 65536, "description": "Optional UTF-8 command input."},
			},
		},
		"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true},
	}
}

func (s *Server) Serve(parent context.Context, input io.ReadCloser, output io.Writer) error {
	if s.Run == nil {
		return errors.New("MCP command runner is required")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { input.Close() })
	defer stop()
	var writeMu sync.Mutex
	var writeErr error
	send := func(id json.RawMessage, result any, failure *rpcError) {
		writeMu.Lock()
		defer writeMu.Unlock()
		if writeErr != nil {
			return
		}
		writeErr = json.NewEncoder(output).Encode(response{JSONRPC: "2.0", ID: id, Result: result, Error: failure})
		if writeErr != nil {
			cancel()
		}
	}
	var callsMu sync.Mutex
	calls := make(map[string]context.CancelFunc)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	initialized, ready := false, false
	baseCaller := caller.Capture(ctx, "mcp")
	type message struct {
		data []byte
		err  error
	}
	messages := make(chan message)
	// Closing a standard input file may leave an OS read blocked until the process exits.
	go func() {
		defer close(messages)
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 4096), 256*1024)
		for scanner.Scan() {
			select {
			case messages <- message{data: bytes.Clone(scanner.Bytes())}:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case messages <- message{err: err}:
			case <-ctx.Done():
			}
		}
	}()
	for {
		var line []byte
		select {
		case <-ctx.Done():
			writeMu.Lock()
			defer writeMu.Unlock()
			return writeErr
		case msg, ok := <-messages:
			if !ok {
				writeMu.Lock()
				defer writeMu.Unlock()
				return writeErr
			}
			if msg.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return msg.err
			}
			line = msg.data
		}
		if !json.Valid(line) || !utf8.Valid(line) {
			send(json.RawMessage("null"), nil, &rpcError{-32700, "invalid JSON"})
			continue
		}
		var req request
		if json.Unmarshal(line, &req) != nil || req.JSONRPC != "2.0" || req.Method == "" || (req.ID != nil && !validID(req.ID)) {
			send(json.RawMessage("null"), nil, &rpcError{-32600, "invalid JSON-RPC request"})
			continue
		}
		if req.ID == nil {
			switch req.Method {
			case "notifications/initialized":
				if initialized {
					ready = true
				}
			case "notifications/cancelled":
				var params struct {
					ID json.RawMessage `json:"requestId"`
				}
				if json.Unmarshal(req.Params, &params) == nil && validID(params.ID) {
					callsMu.Lock()
					if stop := calls[idKey(params.ID)]; stop != nil {
						stop()
					}
					callsMu.Unlock()
				}
			}
			continue
		}
		switch req.Method {
		case "initialize":
			if initialized {
				send(req.ID, nil, &rpcError{-32600, "already initialized"})
				continue
			}
			var params struct {
				ProtocolVersion string `json:"protocolVersion"`
				ClientInfo      struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"clientInfo"`
			}
			if json.Unmarshal(req.Params, &params) != nil || params.ProtocolVersion == "" {
				send(req.ID, nil, &rpcError{-32602, "protocolVersion is required"})
				continue
			}
			candidate := baseCaller
			candidate.ClientName, candidate.ClientVersion = params.ClientInfo.Name, params.ClientInfo.Version
			if err := candidate.Validate(); err != nil {
				send(req.ID, nil, &rpcError{-32602, err.Error()})
				continue
			}
			baseCaller = candidate
			negotiated := params.ProtocolVersion
			if negotiated != version && negotiated != "2025-06-18" {
				negotiated = version
			}
			send(req.ID, map[string]any{"protocolVersion": negotiated, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "lend", "version": "0.1.0"}}, nil)
			initialized = true
		case "ping":
			send(req.ID, map[string]any{}, nil)
		case "tools/list":
			if !ready {
				send(req.ID, nil, &rpcError{-32600, "initialization is required"})
				continue
			}
			send(req.ID, map[string]any{"tools": []any{tool()}}, nil)
		case "tools/call":
			if !ready {
				send(req.ID, nil, &rpcError{-32600, "initialization is required"})
				continue
			}
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if json.Unmarshal(req.Params, &params) != nil || params.Name != "run_local_command" {
				send(req.ID, nil, &rpcError{-32602, "expected run_local_command"})
				continue
			}
			var args toolArgs
			decoder := json.NewDecoder(bytes.NewReader(params.Arguments))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&args) != nil || strings.TrimSpace(args.Reason) == "" || len(args.Stdin) > 65536 {
				send(req.ID, nil, &rpcError{-32602, "expected args, a nonempty reason, and optional stdin up to 65536 bytes"})
				continue
			}
			who := baseCaller
			who.Tool = params.Name
			who.RequestID = idKey(req.ID)[2:]
			command := protocol.Request{Args: args.Args, Reason: args.Reason, Caller: &who}
			if err := command.Validate(); err != nil {
				send(req.ID, nil, &rpcError{-32602, err.Error()})
				continue
			}
			callCtx, callCancel := context.WithCancel(ctx)
			callsMu.Lock()
			if len(calls) >= 32 || calls[idKey(req.ID)] != nil {
				callsMu.Unlock()
				callCancel()
				send(req.ID, nil, &rpcError{-32600, "too many calls or duplicate request ID"})
				continue
			}
			calls[idKey(req.ID)] = callCancel
			callsMu.Unlock()
			wg.Add(1)
			go func(id json.RawMessage, command protocol.Request, input string) {
				defer wg.Done()
				defer callCancel()
				defer func() { callsMu.Lock(); delete(calls, idKey(id)); callsMu.Unlock() }()
				result := s.call(callCtx, command, input)
				if callCtx.Err() == nil {
					send(id, result, nil)
				}
			}(req.ID, command, args.Stdin)
		default:
			send(req.ID, nil, &rpcError{-32601, "method not found"})
		}
	}
}

func validID(id json.RawMessage) bool {
	return idKey(id) != ""
}

func idKey(id json.RawMessage) string {
	var value any
	d := json.NewDecoder(bytes.NewReader(id))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return "s:" + v
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return "n:" + strconv.FormatInt(n, 10)
		}
	}
	return ""
}

type limitedBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > maxOutput-b.Len() {
		b.truncated = true
		p = p[:maxOutput-b.Len()]
	}
	b.Buffer.Write(p)
	return n, nil
}

func (b *limitedBuffer) content() map[string]any {
	value := map[string]any{"truncated": b.truncated}
	if utf8.Valid(b.Bytes()) {
		value["text"] = b.String()
	} else {
		value["base64"] = base64.StdEncoding.EncodeToString(b.Bytes())
	}
	return value
}

func (s *Server) call(ctx context.Context, request protocol.Request, input string) map[string]any {
	var out, stderr limitedBuffer
	code, err := s.Run(ctx, request, strings.NewReader(input), &out, &stderr)
	data := map[string]any{"exit_code": code, "stdout": out.content(), "stderr": stderr.content()}
	if err != nil {
		data["error"] = err.Error()
	}
	text, _ := json.Marshal(data)
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(text)}}, "structuredContent": data, "isError": err != nil || code != 0}
}
