package protocol

import (
	"strings"
	"testing"
)

func TestCallerValidation(t *testing.T) {
	for _, c := range []Caller{
		{Source: "cli", Host: "agent-vm", User: "user", PID: 123, ParentPID: 12, Directory: "/work/project"},
		{Source: "mcp", ClientName: "example-agent", ClientVersion: "1", Tool: "run_local_command", RequestID: "7"},
		{Source: "client"},
	} {
		if err := (Request{Args: []string{"true"}, Caller: &c}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []Caller{
		{Source: "verified"}, {Source: "cli", PID: -1}, {Source: "cli", ParentPID: -1},
		{Source: "cli", Host: strings.Repeat("x", 257)},
		{Source: "mcp", ClientName: "bad\x00name"},
		{Source: "cli", Directory: string([]byte{0xff})},
		{Source: "mcp", RequestID: strings.Repeat("x", 257)},
	} {
		if err := (Request{Args: []string{"true"}, Caller: &c}).Validate(); err == nil {
			t.Fatalf("invalid caller accepted: %+v", c)
		}
	}
}
