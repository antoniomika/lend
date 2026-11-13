package policy

import (
	"errors"

	"github.com/antoniomika/lend/internal/protocol"
)

type ApprovalsPolicy struct {
	Default         string      `json:"default,omitempty"`
	DefaultApproval string      `json:"default_approval,omitempty"`
	Topics          []TopicRule `json:"topics,omitempty"`
}

type TopicRule struct {
	Name     string `json:"name"`
	Approval string `json:"approval"`
}

func (p *ApprovalsPolicy) validate() error {
	if p.Default == "" {
		p.Default = "deny"
	}
	if p.Default != "deny" && p.Default != "allow" {
		return errors.New("approvals default must be deny or allow")
	}
	if p.DefaultApproval == "" {
		p.DefaultApproval = "auto"
	}
	if !validApproval(p.DefaultApproval) {
		return errors.New("invalid approvals default approval")
	}
	seen := make(map[string]bool)
	for _, topic := range p.Topics {
		if !protocol.Topic(topic.Name) || seen[topic.Name] {
			return errors.New("invalid or duplicate approval topic")
		}
		seen[topic.Name] = true
		if !validApproval(topic.Approval) {
			return errors.New("invalid approval topic approval")
		}
	}
	return nil
}

// AuthorizeApproval returns the approval a topic requires before the laptop shows it.
func (p *Policy) AuthorizeApproval(topic string) (string, error) {
	if p == nil {
		return "", errors.New("approval requests require a policy")
	}
	for _, rule := range p.Approvals.Topics {
		if rule.Name == topic {
			return rule.Approval, nil
		}
	}
	if p.Approvals.Default == "allow" {
		return p.Approvals.DefaultApproval, nil
	}
	return "", errors.New("approval topic not allowed")
}
