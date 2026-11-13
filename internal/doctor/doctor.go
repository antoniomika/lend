package doctor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/buildinfo"
	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/control"
	"github.com/antoniomika/lend/internal/device"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/sshagent"
)

type Options struct {
	Config, Profile, Socket, Upstream, Directory, Approval string
	Remote                                                 bool
	Timeout                                                time.Duration
}
type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type Report struct {
	Version  string  `json:"version"`
	Platform string  `json:"platform"`
	Mode     string  `json:"mode"`
	Checks   []Check `json:"checks"`
}

func (r *Report) add(name, status, message string) {
	r.Checks = append(r.Checks, Check{name, status, message})
}
func (r Report) Healthy() bool {
	for _, check := range r.Checks {
		if check.Status == "error" {
			return false
		}
	}
	return true
}

func Run(ctx context.Context, o Options) Report {
	mode := "local"
	if o.Remote {
		mode = "remote"
	}
	r := Report{Version: buildinfo.Version, Platform: runtime.GOOS + "/" + runtime.GOARCH, Mode: mode, Checks: []Check{}}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Remote {
		checkAgent(ctx, &r, "forwarded-agent", o.Socket, true, o.Timeout)
		return r
	}
	var p *policy.Policy
	if o.Config != "" {
		var err error
		p, err = policy.LoadProfile(o.Config, o.Profile)
		if err != nil {
			r.add("policy", "error", err.Error())
		} else {
			r.add("policy", "ok", fmt.Sprintf("loaded %s profile %q", o.Config, o.Profile))
			checkTools(&r, p)
		}
	} else {
		r.add("policy", "warn", "no config supplied; use --config to check command rules and approval requirements")
	}
	if info, err := os.Stat(o.Directory); err != nil || !info.IsDir() {
		r.add("directory", "error", "local working directory does not exist or is not a directory")
	} else {
		r.add("directory", "ok", o.Directory)
	}
	if o.Upstream != "" && o.Socket != "" {
		upstream, _ := filepath.Abs(o.Upstream)
		socket, _ := filepath.Abs(o.Socket)
		if resolved, err := filepath.EvalSymlinks(upstream); err == nil {
			upstream = resolved
		}
		if resolved, err := filepath.EvalSymlinks(socket); err == nil {
			socket = resolved
		}
		if upstream == socket {
			r.add("forwarding-loop", "error", "upstream and proxy select the same socket; use --upstream for the original agent")
		}
	}
	if checkAgent(ctx, &r, "upstream-agent", o.Upstream, false, o.Timeout) {
		keyCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		identities, err := client.ListKeys(keyCtx, o.Upstream)
		cancel()
		if err != nil {
			r.add("upstream-keys", "warn", "agent did not return identities: "+err.Error())
		} else {
			r.add("upstream-keys", "ok", fmt.Sprintf("%d identities available; no signature requested", len(identities)))
			if p != nil {
				checkKeys(&r, p, identities)
			}
		}
	}
	checkSocketDirectory(&r, o.Socket)
	if o.Socket != "" {
		if _, err := os.Lstat(o.Socket); os.IsNotExist(err) {
			r.add("proxy", "warn", "proxy is not running at "+o.Socket)
		} else if checkAgent(ctx, &r, "proxy", o.Socket, true, o.Timeout) {
			controlCtx, cancel := context.WithTimeout(ctx, o.Timeout)
			state, err := control.Call(controlCtx, o.Socket+".control", control.Request{Action: "status"})
			cancel()
			if err != nil {
				r.add("local-control", "warn", err.Error())
			} else if state.Paused {
				r.add("local-control", "warn", "agent is paused; resume it before making requests")
			} else {
				r.add("local-control", "ok", "agent is accepting requests")
			}
		}
	}
	support := approval.Support{}
	if o.Approval != "terminal" {
		support = approval.Inspect()
	}
	checkApproval(&r, p, o.Approval, support)
	if p != nil && p.HasLeases() {
		lockCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		state, err := device.Check(lockCtx)
		cancel()
		if err != nil {
			r.add("lock-tracking", "warn", "leases unavailable: "+err.Error())
		} else if !state.Unlocked {
			r.add("lock-tracking", "warn", "desktop is locked or inactive; leases are unavailable")
		} else {
			r.add("lock-tracking", "ok", "desktop reports unlocked; leases still require an lend ssh session")
		}
	}
	if p != nil && p.History.Path != "" {
		checkHistory(&r, p.History.Path)
	}
	return r
}

func checkAgent(ctx context.Context, r *Report, name, path string, requireLend bool, timeout time.Duration) bool {
	if path == "" {
		r.add(name, "error", "agent socket is unset; specify --socket or --upstream for this mode")
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		r.add(name, "error", err.Error())
		return false
	}
	if info.Mode()&os.ModeSocket == 0 {
		r.add(name, "error", "path is not a Unix socket: "+path)
		return false
	}
	supports, err := probe(ctx, path, timeout)
	if err != nil {
		r.add(name, "error", "agent is unreachable or incompatible: "+err.Error())
		return false
	}
	if requireLend && !supports {
		r.add(name, "error", "agent does not advertise lend; forward the lend proxy socket")
		return false
	}
	message := "SSH agent is reachable"
	if supports {
		message = "lend execution extension is available"
	}
	r.add(name, "ok", message)
	return true
}

func checkTools(r *Report, p *policy.Policy) {
	paths := []string{}
	for _, rule := range p.Commands {
		paths = append(paths, rule.Executable)
	}
	if p.SecretReader != "" {
		paths = append(paths, p.SecretReader)
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || syscall.Access(path, 1) != nil {
			r.add("executable", "error", "configured path is not an executable file: "+path)
		} else {
			r.add("executable", "ok", path)
		}
	}
}

func checkKeys(r *Report, p *policy.Policy, identities []sshagent.Identity) {
	present := make(map[string]bool)
	for _, identity := range identities {
		present[sshagent.Fingerprint(identity.Blob)] = true
	}
	for _, key := range p.SSH.Keys {
		if !present[key.Fingerprint] {
			r.add("configured-key", "warn", key.Fingerprint+" is not currently listed by the upstream agent")
		}
	}
}

func checkApproval(r *Report, p *policy.Policy, mode string, support approval.Support) {
	requirements := []string{}
	if p == nil {
		requirements = append(requirements, "auto")
	} else {
		if p.Default == "allow" {
			requirements = append(requirements, p.DefaultApproval)
			if p.DefaultApproval == "none" {
				r.add("unprompted", "warn", "every command without a matching rule runs without approval")
			}
		}
		if p.SSH.Default == "allow" {
			requirements = append(requirements, p.SSH.DefaultApproval)
			if p.SSH.DefaultApproval == "none" {
				r.add("unprompted", "warn", "every SSH key without a matching rule signs without approval")
			}
		}
		if p.SSH.Management.Default == "allow" {
			requirements = append(requirements, p.SSH.Management.DefaultApproval)
			if p.SSH.Management.DefaultApproval == "none" {
				r.add("unprompted", "warn", "every management operation without a matching rule runs without approval")
			}
		}
		for _, rule := range p.Commands {
			requirements = append(requirements, rule.Approval)
			if rule.Approval == "none" {
				r.add("unprompted", "warn", strings.Join(append([]string{rule.Name}, rule.ArgsPrefix...), " ")+" runs without approval")
			}
		}
		for _, key := range p.SSH.Keys {
			requirements = append(requirements, key.Approval)
			if key.Approval == "none" {
				r.add("unprompted", "warn", "SSH key "+key.Fingerprint+" signs without approval")
			}
		}
		for _, rule := range p.SSH.Management.Operations {
			requirements = append(requirements, rule.Approval)
			if rule.Approval == "none" {
				r.add("unprompted", "warn", "management operation "+rule.Operation+" runs without approval")
			}
		}
	}
	if !slices.ContainsFunc(requirements, func(requirement string) bool { return requirement != "none" }) {
		r.add("approval-backend", "ok", "policy does not require local approval")
		return
	}
	if mode == "terminal" {
		support = approval.Support{Backend: "terminal", Prompt: approval.HasTerminal()}
	}
	if support.Prompt {
		r.add("approval-backend", "ok", support.Backend+" backend detected; no approval was requested")
	} else {
		r.add("approval-backend", "error", "no usable desktop approval backend or controlling terminal; run locally in a terminal or install Zenity")
	}
	if runtime.GOOS == "darwin" && mode == "auto" && support.Backend != "macOS" {
		r.add("native-build", "error", "this build has no native macOS approval support; install a native release or select --approval=terminal")
	}
	if p == nil {
		if runtime.GOOS == "darwin" && mode == "auto" && support.Backend == "macOS" && !support.Authentication {
			r.add("authentication", "error", "macOS auto approval uses device authentication, which is currently unavailable")
		}
		return
	}
	needsAuthentication := slices.Contains(requirements, "authenticate") || (runtime.GOOS == "darwin" && mode == "auto" && support.Backend == "macOS" && slices.Contains(requirements, "auto"))
	if needsAuthentication && !support.Authentication {
		r.add("authentication", "error", "policy requires device authentication, which is unavailable for the selected backend")
	}
	if slices.Contains(requirements, "biometric") && !support.Biometrics {
		r.add("biometrics", "error", "policy requires biometrics, which are unavailable or not enrolled for the selected backend")
	}
}

func checkSocketDirectory(r *Report, path string) {
	if path == "" {
		r.add("socket-directory", "error", "proxy socket path is empty")
		return
	}
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if os.IsNotExist(err) {
		r.add("socket-directory", "ok", "agent will create a private directory at "+directory)
		return
	}
	if err != nil {
		r.add("socket-directory", "error", err.Error())
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0700 {
		r.add("socket-directory", "error", "socket directory must belong to you with mode 0700: "+directory)
		return
	}
	r.add("socket-directory", "ok", directory)
}

func checkHistory(r *Report, path string) {
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if os.IsNotExist(err) {
		r.add("history", "ok", "agent will create a private history directory")
		return
	}
	if err != nil {
		r.add("history", "error", err.Error())
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0700 {
		r.add("history", "error", "history directory must belong to you with mode 0700: "+directory)
		return
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0600 {
			r.add("history", "error", "history must be a regular file owned by you with mode 0600")
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		r.add("history", "error", err.Error())
		return
	}
	r.add("history", "ok", strings.TrimSpace(path))
}
