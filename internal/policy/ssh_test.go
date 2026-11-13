package policy

import (
	"encoding/json"
	"testing"

	"github.com/antoniomika/lend/internal/sshagent"
)

func TestSSHKeyPolicy(t *testing.T) {
	fingerprint := sshagent.Fingerprint([]byte("fixture key"))
	p := parsePolicy(t, Policy{SSH: SSHPolicy{Keys: []KeyRule{{Fingerprint: fingerprint, Label: "git signing", Approval: "biometric", Purposes: []string{"sshsig"}, Namespaces: []string{"git"}, MaxSignatures: 2}}}})
	for _, tc := range []struct {
		name, fingerprint, purpose, namespace string
		allowed                               bool
	}{
		{"allowed", fingerprint, "sshsig", "git", true},
		{"hidden key", sshagent.Fingerprint([]byte("other key")), "sshsig", "git", false},
		{"wrong namespace", fingerprint, "sshsig", "file", false},
		{"auth purpose", fingerprint, "ssh", "", false},
		{"raw purpose", fingerprint, "raw", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := p.AuthorizeSSH(sshagent.SigningRequest{Fingerprint: tc.fingerprint, Purpose: tc.purpose, Namespace: tc.namespace})
			if (err == nil) != tc.allowed {
				t.Fatalf("authorization: %+v %v", key, err)
			}
			if tc.allowed && (key.Approval != "biometric" || key.MaxSignatures != 2) {
				t.Fatalf("lost restrictions: %+v", key)
			}
		})
	}
}

func TestSSHDefaultDenyAndDefaultPurpose(t *testing.T) {
	p, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sshagent.Fingerprint([]byte("fixture"))
	if _, err := p.SSHKey(fingerprint); err == nil {
		t.Fatal("missing ssh policy exposed keys")
	}
	p = parsePolicy(t, Policy{SSH: SSHPolicy{Keys: []KeyRule{{Fingerprint: fingerprint, Approval: "prompt"}}}})
	if _, err := p.AuthorizeSSH(sshagent.SigningRequest{Fingerprint: fingerprint, Purpose: "raw"}); err == nil {
		t.Fatal("default key rule permits raw signing")
	}
	if key, err := p.AuthorizeSSH(sshagent.SigningRequest{Fingerprint: fingerprint, Purpose: "ssh"}); err != nil || key.Approval != "prompt" {
		t.Fatalf("SSH auth denied: %+v %v", key, err)
	}
	if key, err := AllowAll().AuthorizeSSH(sshagent.SigningRequest{Fingerprint: fingerprint, Purpose: "raw"}); err != nil || key.Approval != "auto" {
		t.Fatalf("explicit allow all: %+v %v", key, err)
	}
}

func TestSSHInvalidRules(t *testing.T) {
	fingerprint := sshagent.Fingerprint([]byte("fixture"))
	for _, rule := range []KeyRule{
		{Fingerprint: "SHA256:bad", Approval: "prompt"},
		{Fingerprint: fingerprint, Approval: "none", Lease: &Lease{Duration: "1m", Uses: 1}},
		{Fingerprint: fingerprint, Approval: "prompt", Purposes: []string{"unknown"}},
		{Fingerprint: fingerprint, Approval: "prompt", Namespaces: []string{"git"}},
		{Fingerprint: fingerprint, Approval: "prompt", Purposes: []string{"sshsig"}, Namespaces: []string{""}},
		{Fingerprint: fingerprint, Approval: "prompt", MaxSignatures: -1},
	} {
		data, _ := json.Marshal(Policy{SSH: SSHPolicy{Keys: []KeyRule{rule}}})
		if _, err := Parse(data); err == nil {
			t.Fatalf("accepted invalid rule: %+v", rule)
		}
	}
	for _, data := range []string{`{"ssh":{"default":"anything"}}`, `{"ssh":{"default_approval":"never"}}`, `{"ssh":{"unrecognized":true}}`} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("accepted invalid SSH policy: %s", data)
		}
	}
	data, _ := json.Marshal(Policy{SSH: SSHPolicy{Keys: []KeyRule{{Fingerprint: fingerprint, Approval: "prompt"}, {Fingerprint: fingerprint, Approval: "biometric"}}}})
	if _, err := Parse(data); err == nil {
		t.Fatal("duplicate key policies accepted")
	}
}
