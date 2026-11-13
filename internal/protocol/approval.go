package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	ApproveExtension        = "approve-v1@lend.antoniomika.com"
	AgentSuccess       byte = 6
	MaxApprovalTitle        = 256
	MaxApprovalDetails      = 32 * 1024
)

// ApprovalRequest asks the laptop for a decision without running anything there.
type ApprovalRequest struct {
	Topic   string  `json:"topic"`
	Title   string  `json:"title"`
	Details string  `json:"details,omitempty"`
	Reason  string  `json:"reason,omitempty"`
	Caller  *Caller `json:"caller,omitempty"`
}

func (r ApprovalRequest) Validate() error {
	if r.Caller != nil {
		if err := r.Caller.Validate(); err != nil {
			return err
		}
	}
	if !Topic(r.Topic) {
		return errors.New("topic must be 1 to 64 letters, digits, '-', or '_'")
	}
	for _, field := range []struct {
		name, value string
		limit       int
	}{{"title", r.Title, MaxApprovalTitle}, {"details", r.Details, MaxApprovalDetails}, {"reason", r.Reason, 2048}} {
		if len(field.value) > field.limit || !utf8.ValidString(field.value) || strings.ContainsRune(field.value, 0) {
			return errors.New(field.name + " must be valid UTF-8 without NUL and within its size limit")
		}
	}
	if strings.TrimSpace(r.Title) == "" {
		return errors.New("title is required")
	}
	return nil
}

func Topic(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if c != '-' && c != '_' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func EncodeApproval(r ApprovalRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	p, err := json.Marshal(r)
	return ExtensionPacket(AgentExtension, ApproveExtension, p), err
}

func DecodeApproval(data []byte) (ApprovalRequest, error) {
	var r ApprovalRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return ApprovalRequest{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ApprovalRequest{}, errors.New("unexpected data after approval request")
	}
	return r, r.Validate()
}
