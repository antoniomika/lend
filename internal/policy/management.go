package policy

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/antoniomika/lend/internal/sshagent"
)

type ManagementPolicy struct {
	Default         string           `json:"default,omitempty"`
	DefaultApproval string           `json:"default_approval,omitempty"`
	Operations      []ManagementRule `json:"operations,omitempty"`
}

type ManagementRule struct {
	Operation    string   `json:"operation"`
	Approval     string   `json:"approval"`
	Fingerprints []string `json:"fingerprints,omitempty"`
	Providers    []string `json:"providers,omitempty"`
}

func (p *ManagementPolicy) validate() error {
	if p.Default == "" {
		p.Default = "deny"
	}
	if p.Default != "deny" && p.Default != "allow" {
		return errors.New("management default must be deny or allow")
	}
	if p.DefaultApproval == "" {
		p.DefaultApproval = "auto"
	}
	if !validApproval(p.DefaultApproval) {
		return errors.New("invalid management default approval")
	}
	seen := make(map[string]bool)
	for _, rule := range p.Operations {
		if !sshagent.ManagementOperation(rule.Operation) || seen[rule.Operation] {
			return errors.New("invalid or duplicate management operation")
		}
		seen[rule.Operation] = true
		if !validApproval(rule.Approval) {
			return errors.New("invalid management approval")
		}
		if len(rule.Fingerprints) > 0 && rule.Operation != "add-key" && rule.Operation != "remove-key" {
			return errors.New("fingerprint selection requires add-key or remove-key")
		}
		if len(rule.Providers) > 0 && rule.Operation != "add-key" && rule.Operation != "add-provider" && rule.Operation != "remove-provider" {
			return errors.New("provider selection requires a key or provider load operation")
		}
		for _, fingerprint := range rule.Fingerprints {
			encoded, ok := strings.CutPrefix(fingerprint, "SHA256:")
			blob, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
			if !ok || err != nil || len(blob) != 32 || base64.RawStdEncoding.EncodeToString(blob) != encoded {
				return errors.New("invalid management key fingerprint")
			}
		}
		for _, provider := range rule.Providers {
			if len(provider) == 0 || len(provider) > 4096 || !utf8.ValidString(provider) || strings.ContainsRune(provider, 0) {
				return errors.New("invalid management provider identifier")
			}
		}
	}
	return nil
}

func (p *Policy) AuthorizeManagement(request sshagent.ManagementRequest) (string, error) {
	if p == nil || !sshagent.ManagementOperation(request.Operation) {
		return "", errors.New("management policy is required")
	}
	for _, rule := range p.SSH.Management.Operations {
		if rule.Operation != request.Operation {
			continue
		}
		if len(rule.Fingerprints) > 0 && !slices.Contains(rule.Fingerprints, request.Fingerprint) {
			return "", errors.New("management key not allowed")
		}
		if len(rule.Providers) > 0 && request.Provider != "" && !slices.Contains(rule.Providers, request.Provider) {
			return "", errors.New("management provider not allowed")
		}
		return rule.Approval, nil
	}
	if p.SSH.Management.Default == "allow" && validApproval(p.SSH.Management.DefaultApproval) {
		return p.SSH.Management.DefaultApproval, nil
	}
	return "", errors.New("management operation not allowed")
}
