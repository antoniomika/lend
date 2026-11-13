package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/antoniomika/lend/internal/protocol"
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
		[]byte(`{"default_approval":"none"}`),
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
