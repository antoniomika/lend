package policy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/antoniomika/lend/internal/protocol"
)

func TestProfilesDoNotInheritParentPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	data := []byte(`{"default":"allow","ssh":{"default":"allow"},"profiles":{"development":{"default":"deny"}}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := LoadProfile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := LoadProfile(path, "development")
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.Request{Args: []string{"tool"}}
	if _, err := root.Authorize("/usr/bin/tool", request); err != nil {
		t.Fatal(err)
	}
	if _, err := child.Authorize("/usr/bin/tool", request); err == nil {
		t.Fatal("profile inherited commands")
	}
	if _, err := child.SSHKey("any"); err == nil {
		t.Fatal("profile inherited SSH keys")
	}
	if _, err := LoadProfile(path, "missing"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestLeaseCredentialAndProfileConfiguration(t *testing.T) {
	executable, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	valid := Policy{SecretReader: executable, Commands: []Rule{{Executable: executable, Approval: "biometric", Lease: &Lease{Duration: "5m", Uses: 3}, Secrets: map[string]string{"API_TOKEN": "op://vault/item/token"}}}}
	data, _ := json.Marshal(valid)
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasLeases() {
		t.Fatal("lease was lost")
	}
	result := p.Explain("/", protocol.Request{Args: []string{executable, "-c", "true"}})
	if !result.Allowed || result.Approval != "biometric" || len(result.CredentialVariables) != 1 || result.Lease.Uses != 3 {
		t.Fatalf("incorrect explanation: %+v", result)
	}
	if p.Explain("/", protocol.Request{}).Allowed {
		t.Fatal("empty explanation request allowed")
	}
	invalid := []string{
		`{"profiles":{"../escape":{}}}`,
		`{"profiles":{"nested":{"profiles":{"again":{}}}}}`,
		`{"profiles":{"empty":null}}`,
		`{"history":{"path":"relative"}}`,
	}
	for _, input := range invalid {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	for _, lease := range []*Lease{{Duration: "0s", Uses: 1}, {Duration: "2h", Uses: 1}, {Duration: "1m", Uses: 0}, {Duration: "1m", Uses: 101}, {Duration: "nonsense", Uses: 3}} {
		valid.Commands[0].Lease = lease
		data, _ = json.Marshal(valid)
		if _, err := Parse(data); err == nil {
			t.Fatalf("accepted lease %+v", lease)
		}
	}
	valid.Commands[0].Lease = nil
	for _, secrets := range []map[string]string{{"1TOKEN": "op://vault/item/field"}, {"SSH_AUTH_SOCK": "op://vault/item/field"}, {"TOKEN": ""}, {"TOKEN": "vault/item\nfield"}, {"TOKEN": "op://vault/item\x00/field"}} {
		valid.Commands[0].Secrets = secrets
		data, _ = json.Marshal(valid)
		if _, err := Parse(data); err == nil {
			t.Fatal("invalid credential mapping accepted")
		}
	}
	valid.Commands[0].Secrets = map[string]string{"TOKEN": "op://vault/item/field"}
	valid.SecretReader = ""
	data, _ = json.Marshal(valid)
	if _, err := Parse(data); err == nil {
		t.Fatal("credential mapping accepted without a reader")
	}
	valid.Commands[0].Secrets = nil
	valid.SecretReaderArgs = []string{"read"}
	data, _ = json.Marshal(valid)
	if _, err := Parse(data); err == nil {
		t.Fatal("secret_reader_args accepted without a reader")
	}
}

func TestExplanationUsesLongestPrefixAndReasonRequirement(t *testing.T) {
	executable, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Policy{RequireReason: true, Commands: []Rule{{Executable: executable, Approval: "prompt"}, {Executable: executable, ArgsPrefix: []string{"-c"}, Approval: "biometric"}}})
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.Request{Args: []string{executable, "-c", "true"}}
	if p.Explain("/", request).Allowed {
		t.Fatal("explanation ignored required reason")
	}
	request.Reason = "check command"
	result := p.Explain("/", request)
	if !result.Allowed || result.Approval != "biometric" || len(result.MatchedPrefix) != 1 || result.MatchedRule != "commands[1]" {
		t.Fatalf("wrong match: %+v", result)
	}
}
