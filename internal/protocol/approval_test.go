package protocol

import (
	"strings"
	"testing"
)

func TestApprovalRequestValidation(t *testing.T) {
	valid := ApprovalRequest{Topic: "claude-code", Title: "Run tests", Details: "npm test\n", Reason: "check the change"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]ApprovalRequest{
		"empty topic":     {Title: "x"},
		"topic with dot":  {Topic: "a.b", Title: "x"},
		"blank title":     {Topic: "t", Title: " "},
		"long title":      {Topic: "t", Title: strings.Repeat("x", MaxApprovalTitle+1)},
		"long details":    {Topic: "t", Title: "x", Details: strings.Repeat("x", MaxApprovalDetails+1)},
		"NUL in details":  {Topic: "t", Title: "x", Details: "a\x00b"},
		"invalid UTF-8":   {Topic: "t", Title: "\xff"},
		"long reason":     {Topic: "t", Title: "x", Reason: strings.Repeat("x", 2049)},
		"bad caller":      {Topic: "t", Title: "x", Caller: &Caller{Source: "verified"}},
		"long topic name": {Topic: strings.Repeat("a", 65), Title: "x"},
	} {
		if err := request.Validate(); err == nil {
			t.Fatalf("%s: accepted %+v", name, request)
		}
	}
}

func TestApprovalRequestRoundTrip(t *testing.T) {
	packet, err := EncodeApproval(ApprovalRequest{Topic: "deploy", Title: "Deploy api"})
	if err != nil {
		t.Fatal(err)
	}
	name, data, err := ParseExtension(packet)
	if err != nil || name != ApproveExtension {
		t.Fatalf("name=%q err=%v", name, err)
	}
	request, err := DecodeApproval(data)
	if err != nil || request.Topic != "deploy" || request.Title != "Deploy api" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	for _, data := range []string{`{"topic":"t","title":"x","verified":true}`, `{"topic":"t","title":"x"} {}`} {
		if _, err := DecodeApproval([]byte(data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
