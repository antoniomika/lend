package policy

import (
	"encoding/json"
	"testing"

	"github.com/antoniomika/lend/internal/sshagent"
)

func TestManagementPermissionsAndScopes(t *testing.T) {
	fingerprint := sshagent.Fingerprint([]byte("fixture"))
	p := parsePolicy(t, Policy{SSH: SSHPolicy{Management: ManagementPolicy{Operations: []ManagementRule{
		{Operation: "add-key", Approval: "biometric", Fingerprints: []string{fingerprint}, Providers: []string{"internal"}},
		{Operation: "remove-key", Approval: "prompt", Fingerprints: []string{fingerprint}},
		{Operation: "add-provider", Approval: "authenticate", Providers: []string{"/example/provider.so"}},
		{Operation: "lock", Approval: "biometric"},
	}}}})
	for _, tc := range []struct {
		request sshagent.ManagementRequest
		mode    string
	}{
		{sshagent.ManagementRequest{Operation: "add-key", Fingerprint: fingerprint}, "biometric"},
		{sshagent.ManagementRequest{Operation: "add-key", Fingerprint: fingerprint, Provider: "internal"}, "biometric"},
		{sshagent.ManagementRequest{Operation: "add-key", Fingerprint: fingerprint, Provider: "/wrong"}, ""},
		{sshagent.ManagementRequest{Operation: "add-key", Fingerprint: sshagent.Fingerprint([]byte("other"))}, ""},
		{sshagent.ManagementRequest{Operation: "remove-key", Fingerprint: fingerprint}, "prompt"},
		{sshagent.ManagementRequest{Operation: "remove-all-keys"}, ""},
		{sshagent.ManagementRequest{Operation: "lock"}, "biometric"},
		{sshagent.ManagementRequest{Operation: "unlock"}, ""},
		{sshagent.ManagementRequest{Operation: "add-provider", Provider: "/example/provider.so"}, "authenticate"},
		{sshagent.ManagementRequest{Operation: "add-provider", Provider: "/wrong"}, ""},
	} {
		mode, err := p.AuthorizeManagement(tc.request)
		if tc.mode == "" {
			if err == nil {
				t.Fatal("unlisted management target allowed")
			}
		} else if err != nil || mode != tc.mode {
			t.Fatalf("management approval %q: %v", mode, err)
		}
	}
	if _, err := p.SSHKey(fingerprint); err == nil {
		t.Fatal("key management permission also granted signing")
	}
}

func TestManagementDefaultAndInvalidRules(t *testing.T) {
	p, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.AuthorizeManagement(sshagent.ManagementRequest{Operation: "lock"}); err == nil {
		t.Fatal("missing management policy permits changes")
	}
	if mode, err := AllowAll().AuthorizeManagement(sshagent.ManagementRequest{Operation: "lock"}); err != nil || mode != "auto" {
		t.Fatal("explicit allow all excludes management")
	}
	for _, rule := range []ManagementRule{
		{Operation: "unknown", Approval: "prompt"}, {Operation: "lock", Approval: "never"},
		{Operation: "remove-all-keys", Approval: "prompt", Fingerprints: []string{sshagent.Fingerprint([]byte("fixture"))}},
		{Operation: "unlock", Approval: "prompt", Providers: []string{"internal"}},
		{Operation: "add-key", Approval: "prompt", Fingerprints: []string{"SHA256:bad"}},
		{Operation: "add-provider", Approval: "prompt", Providers: []string{"bad\x00provider"}},
	} {
		data, _ := json.Marshal(Policy{SSH: SSHPolicy{Management: ManagementPolicy{Operations: []ManagementRule{rule}}}})
		if _, err := Parse(data); err == nil {
			t.Fatal("invalid management policy accepted")
		}
	}
	for _, data := range []string{
		`{"ssh":{"management":{"default":"bad"}}}`, `{"ssh":{"management":{"default_approval":"never"}}}`,
		`{"ssh":{"management":{"operations":[{"operation":"lock","approval":"prompt"},{"operation":"lock","approval":"biometric"}]}}}`,
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatal("invalid management configuration accepted")
		}
	}
}
