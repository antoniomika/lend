package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/antoniomika/lend/internal/protocol"
)

type Rule struct {
	Source     string            `json:"-"`
	Executable string            `json:"executable"`
	ArgsPrefix []string          `json:"args_prefix,omitempty"`
	Approval   string            `json:"approval"`
	Lease      *Lease            `json:"lease,omitempty"`
	Secrets    map[string]string `json:"secrets,omitempty"`
}

type Policy struct {
	Default         string             `json:"default"`
	DefaultApproval string             `json:"default_approval,omitempty"`
	RequireReason   bool               `json:"require_reason,omitempty"`
	Commands        []Rule             `json:"commands"`
	SSH             SSHPolicy          `json:"ssh"`
	Profiles        map[string]*Policy `json:"profiles,omitempty"`
	SecretReader    string             `json:"secret_reader,omitempty"`
	History         History            `json:"history,omitempty"`
}

func AllowAll() *Policy {
	return &Policy{Default: "allow", DefaultApproval: "auto", SSH: SSHPolicy{Default: "allow", DefaultApproval: "auto", Management: ManagementPolicy{Default: "allow", DefaultApproval: "auto"}}}
}

func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("policy exceeds 1 MiB")
	}
	return Parse(data)
}

func Parse(data []byte) (*Policy, error) {
	var p Policy
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("unexpected data after policy")
	}
	if err := p.validate(false); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate(nested bool) error {
	if nested && len(p.Profiles) != 0 {
		return errors.New("profiles cannot contain profiles")
	}
	for name, profile := range p.Profiles {
		if !identifier(name) || profile == nil {
			return errors.New("invalid profile name or policy")
		}
		if err := profile.validate(true); err != nil {
			return fmt.Errorf("profile %s: %w", name, err)
		}
	}
	if p.History.Path != "" && !filepath.IsAbs(p.History.Path) {
		return errors.New("history path must be absolute")
	}
	if p.SecretReader != "" {
		if !filepath.IsAbs(p.SecretReader) {
			return errors.New("secret_reader must be an absolute executable path")
		}
		resolved, err := filepath.EvalSymlinks(p.SecretReader)
		if err != nil {
			return fmt.Errorf("resolve secret reader: %w", err)
		}
		p.SecretReader = resolved
	}
	if p.Default == "" {
		p.Default = "deny"
	}
	if p.Default != "deny" && p.Default != "allow" {
		return errors.New("policy default must be deny or allow")
	}
	if p.DefaultApproval == "" {
		p.DefaultApproval = "auto"
	}
	if !validApproval(p.DefaultApproval) {
		return fmt.Errorf("invalid default approval %q", p.DefaultApproval)
	}
	if err := p.SSH.validate(); err != nil {
		return err
	}
	for i := range p.Commands {
		rule := &p.Commands[i]
		if !filepath.IsAbs(rule.Executable) {
			return errors.New("policy executables must be absolute paths")
		}
		resolved, err := filepath.EvalSymlinks(rule.Executable)
		if err != nil {
			return fmt.Errorf("resolve policy executable: %w", err)
		}
		rule.Executable = resolved
		if !validApproval(rule.Approval) {
			return fmt.Errorf("invalid approval %q", rule.Approval)
		}
		if err := (protocol.Request{Args: append([]string{resolved}, rule.ArgsPrefix...)}).Validate(); err != nil {
			return err
		}
		if err := rule.Lease.validate(); err != nil {
			return err
		}
		if len(rule.Secrets) > 32 {
			return errors.New("at most 32 credential variables are allowed")
		}
		for name, ref := range rule.Secrets {
			if !envName(name) || name == "SSH_AUTH_SOCK" || !strings.HasPrefix(ref, "op://") || len(ref) > 2048 || strings.ContainsAny(ref, "\x00\r\n") || len(ref) <= 5 {
				return errors.New("invalid credential environment variable or 1Password reference")
			}
			if p.SecretReader == "" {
				return errors.New("credential injection requires secret_reader")
			}
		}
		for _, previous := range p.Commands[:i] {
			if previous.Executable == resolved && slices.Equal(previous.ArgsPrefix, rule.ArgsPrefix) {
				return errors.New("duplicate command rule")
			}
		}
	}
	return nil
}

func validApproval(value string) bool {
	return value == "auto" || value == "prompt" || value == "authenticate" || value == "biometric"
}

func (p *Policy) Authorize(executable string, request protocol.Request) (string, error) {
	rule, err := p.Command(executable, request)
	return rule.Approval, err
}

func (p *Policy) Command(executable string, request protocol.Request) (Rule, error) {
	if p == nil {
		return Rule{}, errors.New("command execution requires a policy")
	}
	if err := request.Validate(); err != nil {
		return Rule{}, err
	}
	if p.RequireReason && strings.TrimSpace(request.Reason) == "" {
		return Rule{}, errors.New("a reason is required")
	}
	best := -1
	matched := Rule{}
	for i, rule := range p.Commands {
		args := request.Args[1:]
		if rule.Executable == executable && len(args) >= len(rule.ArgsPrefix) && slices.Equal(args[:len(rule.ArgsPrefix)], rule.ArgsPrefix) && len(rule.ArgsPrefix) > best {
			best = len(rule.ArgsPrefix)
			matched = rule
			matched.Source = fmt.Sprintf("commands[%d]", i)
		}
	}
	if best >= 0 {
		return matched, nil
	}
	if p.Default == "allow" && validApproval(p.DefaultApproval) {
		return Rule{Executable: executable, Approval: p.DefaultApproval, Source: "default"}, nil
	}
	return Rule{}, errors.New("command is not allowed by local policy")
}
