package policy

import "testing"

func TestApprovalTopics(t *testing.T) {
	p, err := Parse([]byte(`{"approvals":{"topics":[{"name":"claude-code","approval":"biometric:inline"},{"name":"notes","approval":"prompt"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if approval, err := p.AuthorizeApproval("claude-code"); err != nil || approval != "biometric:inline" {
		t.Fatalf("approval=%q err=%v", approval, err)
	}
	if _, err := p.AuthorizeApproval("deploy"); err == nil {
		t.Fatal("default deny allowed an unlisted topic")
	}
	p, err = Parse([]byte(`{"approvals":{"default":"allow","default_approval":"biometric"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if approval, err := p.AuthorizeApproval("deploy"); err != nil || approval != "biometric" {
		t.Fatalf("approval=%q err=%v", approval, err)
	}
	if _, err := (&Policy{}).AuthorizeApproval("deploy"); err == nil {
		t.Fatal("empty policy allowed a topic")
	}
}

func TestInvalidApprovalTopics(t *testing.T) {
	for _, data := range []string{
		`{"approvals":{"default":"maybe"}}`,
		`{"approvals":{"default_approval":"never"}}`,
		`{"approvals":{"topics":[{"name":"a.b","approval":"prompt"}]}}`,
		`{"approvals":{"topics":[{"name":"a","approval":"prompt"},{"name":"a","approval":"auto"}]}}`,
		`{"approvals":{"topics":[{"name":"a","approval":""}]}}`,
		`{"approvals":{"topics":[{"name":"a","approval":"prompt","lease":{}}]}}`,
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
