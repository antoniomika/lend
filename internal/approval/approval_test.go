package approval

import (
	"context"
	"strings"
	"testing"

	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/protocol"
)

func TestPromptEscapesUntrustedArguments(t *testing.T) {
	s := Summary{Executable: "/bin/printf", Args: []string{"printf", "\x1b[2J\n\r\u202eallow"}, Directory: "/home/example"}.String()
	for _, control := range []string{"\x1b", "\r", "\u202e"} {
		if strings.Contains(s, control) {
			t.Fatalf("prompt contains control %q", control)
		}
	}
	if !strings.Contains(s, `\x1b[2J\n\r\u202eallow`) {
		t.Fatalf("missing escaped argument: %s", s)
	}
}

func TestCallerPromptSeparatesReportedAndObservedInfo(t *testing.T) {
	uid := uint32(1000)
	s := Summary{
		Caller:   &protocol.Caller{Source: "mcp", Host: "agent-vm\nOrigin: verified\x1b[2J", User: "user", PID: 123, ParentPID: 12, Directory: "/work/project", ClientName: "example-agent", ClientVersion: "1", Tool: "run_local_command", RequestID: "7"},
		Peer:     &caller.Peer{PID: 99, UID: &uid, Process: "/usr/bin/ssh"},
		Bindings: []SSHBinding{{Fingerprint: "SHA256:fixture", Forwarding: true}},
	}.String()
	for _, want := range []string{"Caller (requester supplied, unverified)", `agent-vm\nOrigin: verified\x1b[2J`, "Local socket peer (kernel-reported at connection)", "/usr/bin/ssh", "example-agent", "run_local_command", "Request ID", "upstream accepted, unverified by lend", "SHA256:fixture"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing caller detail %q", want)
		}
	}
	if strings.Contains(s, "\nOrigin: verified") || strings.ContainsRune(s, '\x1b') {
		t.Fatal("reported caller injected prompt text")
	}
}

func TestMissingCallerRemainsUnknown(t *testing.T) {
	for _, kind := range []string{"", "ssh-sign"} {
		s := Summary{Kind: kind}.String()
		if !strings.Contains(s, "Caller details: unavailable") || strings.Contains(s, "kernel-reported at connection") {
			t.Fatal("missing metadata created caller identity")
		}
	}
}

func TestTerminalCannotDowngradeAuthentication(t *testing.T) {
	approve, err := New("terminal")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"biometric", "biometric:inline", "biometric:separate", "authenticate"} {
		if err := approve(context.Background(), Summary{Requirement: mode}); err == nil {
			t.Fatalf("terminal satisfied %s", mode)
		}
		decide, err := NewDecider("terminal")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decide(context.Background(), Summary{Requirement: mode, Lease: &LeaseOffer{Duration: "1m", Uses: 3}}); err == nil {
			t.Fatal("lease weakened authentication")
		}
	}
}

func TestReasonIsEscapedAndLabeled(t *testing.T) {
	s := Summary{Reason: "inspect\nExecutable: trusted\x1b[2J"}.String()
	if !strings.Contains(s, `Reason (requester supplied): "inspect\nExecutable: trusted\x1b[2J"`) {
		t.Fatalf("reason can change prompt layout: %s", s)
	}
}

func TestSSHSigningPrompt(t *testing.T) {
	s := Summary{Kind: "ssh-sign", KeyFingerprint: "SHA256:fixture", KeyType: "ssh-ed25519", KeyLabel: "key\n\x1b[2J", SigningPurpose: "sshsig", SigningNamespace: "git", SigningDigest: "SHA256:digest", SigningBytes: 75}.String()
	for _, want := range []string{"SSH key", "SHA256:fixture", `key\n\x1b[2J`, "git", "75 bytes", "SHA256:digest"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing signing detail %q: %s", want, s)
		}
	}
	if strings.Contains(s, "Executable:") || strings.ContainsRune(s, '\x1b') {
		t.Fatal("signing prompt contains command fields or terminal controls")
	}
}

func TestApprovalRequestSummaryEscapesDetails(t *testing.T) {
	s := Summary{Kind: "approval", Topic: "claude-code", Title: "Run\x1b[2J", Details: "echo \"hi\" \\\n\tnext\x07 é"}.String()
	for _, want := range []string{"Nothing runs on this computer.", `Topic: "claude-code"`, `Title (requester supplied): "Run\x1b[2J"`, `  echo "hi" \`, `      next\a \u00e9`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	if strings.ContainsAny(s, "\x1b\x07\t") {
		t.Fatalf("control characters reached the prompt:\n%s", s)
	}
}
