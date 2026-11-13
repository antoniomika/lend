package policy

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/antoniomika/lend/internal/protocol"
)

type Lease struct {
	Duration string `json:"duration"`
	Uses     int    `json:"uses"`
}

func (l *Lease) validate() error {
	if l == nil {
		return nil
	}
	d, err := time.ParseDuration(l.Duration)
	if err != nil || d <= 0 || d > time.Hour || l.Uses < 1 || l.Uses > 100 {
		return errors.New("lease requires a duration up to 1h and 1 to 100 uses")
	}
	return nil
}

type History struct {
	Path         string `json:"path,omitempty"`
	LogArguments bool   `json:"log_arguments,omitempty"`
}

func identifier(s string) bool {
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

func envName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if c != '_' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func LoadProfile(path, name string) (*Policy, error) {
	p, err := Load(path)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return p, nil
	}
	selected, ok := p.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q does not exist", name)
	}
	return selected, nil
}

func Resolve(command, directory string) (string, error) {
	if strings.ContainsRune(command, '/') && !filepath.IsAbs(command) {
		command = filepath.Join(directory, command)
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

type Explanation struct {
	MatchedRule         string   `json:"matched_rule,omitempty"`
	Allowed             bool     `json:"allowed"`
	Executable          string   `json:"executable,omitempty"`
	Approval            string   `json:"approval,omitempty"`
	MatchedPrefix       []string `json:"matched_prefix,omitempty"`
	Lease               *Lease   `json:"lease,omitempty"`
	CredentialVariables []string `json:"credential_variables,omitempty"`
	Error               string   `json:"error,omitempty"`
}

func (p *Policy) Explain(directory string, request protocol.Request) Explanation {
	if err := request.Validate(); err != nil {
		return Explanation{Error: err.Error()}
	}
	path, err := Resolve(request.Args[0], directory)
	result := Explanation{Executable: path}
	if err == nil {
		var rule Rule
		rule, err = p.Command(path, request)
		if err == nil {
			result.Allowed = true
			result.MatchedRule = rule.Source
			result.Approval = rule.Approval
			result.MatchedPrefix = rule.ArgsPrefix
			result.Lease = rule.Lease
			for name := range rule.Secrets {
				result.CredentialVariables = append(result.CredentialVariables, name)
			}
		}
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func (p *Policy) HasLeases() bool {
	for _, rule := range p.Commands {
		if rule.Lease != nil {
			return true
		}
	}
	for _, key := range p.SSH.Keys {
		if key.Lease != nil {
			return true
		}
	}
	return false
}
