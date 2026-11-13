package policy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/antoniomika/lend/internal/sshagent"
)

type SSHPolicy struct {
	Default         string           `json:"default,omitempty"`
	DefaultApproval string           `json:"default_approval,omitempty"`
	Keys            []KeyRule        `json:"keys,omitempty"`
	Management      ManagementPolicy `json:"management"`
}

type KeyRule struct {
	Fingerprint   string   `json:"fingerprint"`
	Label         string   `json:"label,omitempty"`
	Approval      string   `json:"approval"`
	Purposes      []string `json:"purposes,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"`
	MaxSignatures int      `json:"max_signatures,omitempty"`
	Lease         *Lease   `json:"lease,omitempty"`
}

func (p *SSHPolicy) validate() error {
	if err := p.Management.validate(); err != nil {
		return err
	}
	if p.Default == "" {
		p.Default = "deny"
	}
	if p.Default != "deny" && p.Default != "allow" {
		return errors.New("ssh default must be deny or allow")
	}
	if p.DefaultApproval == "" {
		p.DefaultApproval = "auto"
	}
	if !validApproval(p.DefaultApproval) {
		return errors.New("invalid ssh default approval")
	}
	for i := range p.Keys {
		key := &p.Keys[i]
		if err := key.Lease.validate(); err != nil {
			return err
		}
		encoded, ok := strings.CutPrefix(key.Fingerprint, "SHA256:")
		blob, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
		if !ok || err != nil || len(blob) != 32 || base64.RawStdEncoding.EncodeToString(blob) != encoded {
			return errors.New("key fingerprint must be an unpadded SHA256 fingerprint")
		}
		if !validApproval(key.Approval) {
			return errors.New("invalid SSH key approval")
		}
		if key.Approval == "none" && key.Lease != nil {
			return errors.New(`approval "none" does not use a lease`)
		}
		if len(key.Label) > 256 || !utf8.ValidString(key.Label) || strings.ContainsRune(key.Label, 0) {
			return errors.New("invalid SSH key label")
		}
		if key.MaxSignatures < 0 {
			return errors.New("max_signatures cannot be negative")
		}
		if len(key.Purposes) == 0 {
			key.Purposes = []string{"ssh"}
		}
		for _, purpose := range key.Purposes {
			if purpose != "ssh" && purpose != "sshsig" && purpose != "raw" {
				return fmt.Errorf("unknown SSH key purpose %q", purpose)
			}
		}
		if len(key.Namespaces) != 0 && !slices.Contains(key.Purposes, "sshsig") {
			return errors.New("namespace restrictions require the sshsig purpose")
		}
		for _, namespace := range key.Namespaces {
			if len(namespace) == 0 || len(namespace) > 256 || !utf8.ValidString(namespace) || strings.ContainsRune(namespace, 0) {
				return errors.New("invalid SSHSIG namespace")
			}
		}
		for _, previous := range p.Keys[:i] {
			if previous.Fingerprint == key.Fingerprint {
				return errors.New("duplicate SSH key fingerprint")
			}
		}
	}
	return nil
}

func (p *Policy) SSHKey(fingerprint string) (KeyRule, error) {
	if p == nil {
		return KeyRule{}, errors.New("SSH key use requires a policy")
	}
	for _, key := range p.SSH.Keys {
		if key.Fingerprint == fingerprint {
			return key, nil
		}
	}
	if p.SSH.Default == "allow" && validApproval(p.SSH.DefaultApproval) {
		return KeyRule{Fingerprint: fingerprint, Approval: p.SSH.DefaultApproval}, nil
	}
	return KeyRule{}, errors.New("SSH key is not allowed by local policy")
}

func (p *Policy) AuthorizeSSH(request sshagent.SigningRequest) (KeyRule, error) {
	key, err := p.SSHKey(request.Fingerprint)
	if err != nil {
		return key, err
	}
	if len(key.Purposes) > 0 && !slices.Contains(key.Purposes, request.Purpose) {
		return key, errors.New("SSH signing purpose is not allowed")
	}
	if request.Purpose == "sshsig" && len(key.Namespaces) > 0 && !slices.Contains(key.Namespaces, request.Namespace) {
		return key, errors.New("SSHSIG namespace is not allowed")
	}
	return key, nil
}
