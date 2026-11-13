package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func executable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// Callers pass canonical paths, and macOS temp dirs sit under the /var symlink.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func parsePolicy(t *testing.T, p Policy) *Policy {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCommandRulesAndApproval(t *testing.T) {
	path := executable(t)
	p := parsePolicy(t, Policy{Default: "deny", RequireReason: true, Commands: []Rule{
		{Executable: path, ArgsPrefix: []string{"read"}, Approval: "biometric"},
		{Executable: path, ArgsPrefix: []string{"item"}, Approval: "authenticate"},
		{Executable: path, ArgsPrefix: []string{"item", "get"}, Approval: "prompt"},
	}})
	for _, tc := range []struct {
		name, exe, reason, want string
		args                    []string
	}{
		{"read", path, "fetch credential", "biometric", []string{"tool", "read", "op://example/key"}},
		{"specific rule", path, "inspect item", "prompt", []string{"tool", "item", "get", "example"}},
		{"general rule", path, "list items", "authenticate", []string{"tool", "item", "list"}},
		{"prefix boundary", path, "fetch credential", "", []string{"tool", "reader"}},
		{"other executable", filepath.Join(filepath.Dir(path), "other"), "fetch credential", "", []string{"tool", "read"}},
		{"missing reason", path, "  ", "", []string{"tool", "read"}},
		{"empty command", path, "inspect", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.Authorize(tc.exe, protocol.Request{Args: tc.args, Reason: tc.reason})
			if tc.want == "" {
				if err == nil {
					t.Fatal("unlisted command allowed")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("approval=%q err=%v", got, err)
			}
		})
	}
}

func TestDefaultDenyAndExplicitAllow(t *testing.T) {
	p, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	r := protocol.Request{Args: []string{"tool"}}
	if _, err := p.Authorize("/example/tool", r); err == nil {
		t.Fatal("empty policy allows execution")
	}
	p = parsePolicy(t, Policy{Default: "allow", DefaultApproval: "prompt"})
	if mode, err := p.Authorize("/example/tool", r); err != nil || mode != "prompt" {
		t.Fatalf("%s %v", mode, err)
	}
	var missing *Policy
	if _, err := missing.Authorize("/example/tool", r); err == nil {
		t.Fatal("missing policy allows execution")
	}
}

func TestPolicyCanonicalizesSymlinks(t *testing.T) {
	path := executable(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	p := parsePolicy(t, Policy{Commands: []Rule{{Executable: alias, Approval: "biometric"}}})
	if mode, err := p.Authorize(path, protocol.Request{Args: []string{"alias"}}); err != nil || mode != "biometric" {
		t.Fatalf("%s %v", mode, err)
	}
}

func TestInvalidPolicies(t *testing.T) {
	path := executable(t)
	duplicate, _ := json.Marshal(Policy{Commands: []Rule{{Executable: path, Approval: "prompt"}, {Executable: path, Approval: "biometric"}}})
	for _, data := range [][]byte{
		[]byte(`{"default":"anything"}`),
		[]byte(`{"default_approval":"never"}`),
		[]byte(`{"default_approval":"biometric:popup"}`),
		[]byte(`{"commands":[{"executable":"tool","approval":"prompt"}]}`),
		[]byte(`{"default":"allow","typo":true}`),
		[]byte(`{} {}`), duplicate,
	} {
		if _, err := Parse(data); err == nil {
			t.Fatalf("accepted invalid policy: %s", data)
		}
	}
}

func TestExplainReportsConfiguredArgv0(t *testing.T) {
	path := executable(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	p := parsePolicy(t, Policy{Commands: []Rule{{Executable: alias, Approval: "prompt"}}})
	if got := p.Explain(t.TempDir(), protocol.Request{Args: []string{path}}); !got.Allowed || got.Argv0 != alias {
		t.Fatalf("%+v", got)
	}
	open := parsePolicy(t, Policy{Default: "allow"})
	if got := open.Explain(t.TempDir(), protocol.Request{Args: []string{path}}); !got.Allowed || got.Argv0 != "" {
		t.Fatalf("%+v", got)
	}
}

func TestUnpromptedCommands(t *testing.T) {
	path := executable(t)
	p := parsePolicy(t, Policy{Commands: []Rule{
		{Executable: path, Approval: "biometric"},
		{Executable: path, ArgsPrefix: []string{"pr", "view"}, Approval: "none"},
	}})
	if got, err := p.Authorize(path, protocol.Request{Args: []string{"tool", "pr", "view", "1"}}); err != nil || got != "none" {
		t.Fatalf("approval=%q err=%v", got, err)
	}
	if got, err := p.Authorize(path, protocol.Request{Args: []string{"tool", "pr", "merge", "1"}}); err != nil || got != "biometric" {
		t.Fatalf("approval=%q err=%v", got, err)
	}
	whole := parsePolicy(t, Policy{Commands: []Rule{{Executable: path, Approval: "none"}}})
	if got, err := whole.Authorize(path, protocol.Request{Args: []string{"tool", "anything"}}); err != nil || got != "none" {
		t.Fatalf("approval=%q err=%v", got, err)
	}
	open := parsePolicy(t, Policy{Default: "allow", DefaultApproval: "none"})
	if got, err := open.Authorize("/example/tool", protocol.Request{Args: []string{"tool"}}); err != nil || got != "none" {
		t.Fatalf("approval=%q err=%v", got, err)
	}
	keys := parsePolicy(t, Policy{SSH: SSHPolicy{Default: "allow", DefaultApproval: "none", Keys: []KeyRule{{Fingerprint: "SHA256:Hvkm6UfgfD4K25mObdMYLV+11J532Dayhqtj6BccZ74", Approval: "none"}}}})
	for _, fingerprint := range []string{"SHA256:Hvkm6UfgfD4K25mObdMYLV+11J532Dayhqtj6BccZ74", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if key, err := keys.SSHKey(fingerprint); err != nil || key.Approval != "none" {
			t.Fatalf("%s: approval=%q err=%v", fingerprint, key.Approval, err)
		}
	}
	unprompted := parsePolicy(t, Policy{SecretReader: path, Commands: []Rule{{Executable: path, ArgsPrefix: []string{"read"}, Approval: "none", Secrets: map[string]string{"TOKEN": "op://vault/item/field"}}}, SSH: SSHPolicy{Management: ManagementPolicy{Default: "allow", DefaultApproval: "none", Operations: []ManagementRule{{Operation: "lock", Approval: "none"}}}}})
	if got, err := unprompted.Authorize(path, protocol.Request{Args: []string{"tool", "read"}}); err != nil || got != "none" {
		t.Fatalf("secrets: approval=%q err=%v", got, err)
	}
	for _, operation := range []string{"lock", "unlock"} {
		if got, err := unprompted.AuthorizeManagement(sshagent.ManagementRequest{Operation: operation}); err != nil || got != "none" {
			t.Fatalf("%s: approval=%q err=%v", operation, got, err)
		}
	}
	for name, invalid := range map[string]Policy{
		"command lease": {Commands: []Rule{{Executable: path, Approval: "none", Lease: &Lease{Duration: "1m", Uses: 1}}}},
		"ssh key lease": {SSH: SSHPolicy{Keys: []KeyRule{{Fingerprint: "SHA256:Hvkm6UfgfD4K25mObdMYLV+11J532Dayhqtj6BccZ74", Approval: "none", Lease: &Lease{Duration: "1m", Uses: 1}}}}},
	} {
		data, _ := json.Marshal(invalid)
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted unused lease: %s", name, data)
		}
	}
}
