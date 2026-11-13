package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antoniomika/lend/internal/activity"
	"github.com/antoniomika/lend/internal/control"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func administer(ctx context.Context, action string, args []string) (int, error) {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	socket := fs.String("socket", defaultSocket(), "local agent socket (never the forwarded SSH_AUTH_SOCK)")
	all := fs.Bool("all", false, "operate on the default agent and all lend ssh sessions")
	watch := fs.Bool("watch", false, "refresh the local activity view every second")
	asJSON := fs.Bool("json", false, "print JSON")
	file := fs.String("file", "", "read a persistent history file after the session ends")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if *watch && action != "status" {
		return 2, errors.New("--watch is available for status")
	}
	if action == "revoke" {
		if fs.NArg() != 1 {
			return 2, errors.New("revoke requires an activity ID")
		}
	} else if fs.NArg() > 1 || (fs.NArg() == 1 && action != "clear-leases") {
		return 2, errors.New("unexpected positional arguments")
	}
	if *all && *socket != defaultSocket() {
		return 2, errors.New("choose --all or --socket")
	}
	if *file != "" {
		if action != "history" || *all || fs.NArg() != 0 || *socket != defaultSocket() {
			return 2, errors.New("--file is available only for history and cannot be combined with --all or --socket")
		}
		entries, err := activity.ReadHistory(*file)
		if err != nil {
			return 1, err
		}
		if *asJSON {
			err = json.NewEncoder(os.Stdout).Encode(struct {
				File    string           `json:"file"`
				History []activity.Entry `json:"history"`
			}{*file, entries})
		} else {
			renderActivity(*file, control.Response{Snapshot: activity.Snapshot{History: entries}}, true)
		}
		return 0, err
	}
	for {
		sockets := []string{*socket}
		if *all {
			sockets = localSockets()
		}
		if len(sockets) == 0 {
			return 1, errors.New("no local agents found")
		}
		if *watch && !*asJSON {
			if info, err := os.Stdout.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
				fmt.Fprint(os.Stdout, "\x1b[H\x1b[2J")
			}
		}
		failed := false
		for _, path := range sockets {
			id := ""
			if fs.NArg() == 1 {
				id = fs.Arg(0)
			}
			response, err := control.Call(ctx, path+".control", control.Request{Action: action, ID: id})
			if err != nil {
				failed = true
				fmt.Fprintf(os.Stderr, "%s: %v\n", strconv.QuoteToASCII(path), err)
				continue
			}
			if *asJSON {
				if err := json.NewEncoder(os.Stdout).Encode(struct {
					Socket string `json:"socket"`
					control.Response
				}{path, response}); err != nil {
					return 1, err
				}
			} else {
				renderActivity(path, response, action == "history")
			}
		}
		if !*watch {
			if failed {
				return 1, nil
			}
			return 0, nil
		}
		select {
		case <-ctx.Done():
			return 0, nil
		case <-time.After(time.Second):
		}
	}
}

func localSockets() []string {
	root := filepath.Dir(defaultSocket())
	paths := []string{}
	candidates := []string{defaultSocket()}
	sessions, _ := filepath.Glob(filepath.Join(root, "session-*", "agent.sock.control"))
	for _, path := range sessions {
		candidates = append(candidates, strings.TrimSuffix(path, ".control"))
	}
	for _, path := range candidates {
		if info, err := os.Lstat(path + ".control"); err == nil && info.Mode()&os.ModeSocket != 0 {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

func renderActivity(socket string, response control.Response, history bool) {
	fmt.Fprintf(os.Stdout, "Session %s socket=%s paused=%t lease_tracking=%s\n", strconv.QuoteToASCII(response.Session), strconv.QuoteToASCII(socket), response.Paused, strconv.QuoteToASCII(response.LeaseTracking))
	entries := response.Active
	if history {
		entries = response.History
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Started.Before(entries[j].Started) })
	for _, entry := range entries {
		target := entry.Executable
		if target == "" {
			target = entry.Fingerprint
		}
		if entry.Operation != "" {
			target = entry.Operation + " " + target
		}
		if entry.Topic != "" {
			target = entry.Topic
			if entry.Info != nil {
				target += " " + entry.Info.Title
			}
		}
		fmt.Fprintf(os.Stdout, "  %s %-11s %-12s %s", entry.ID, entry.Kind, entry.State, strconv.QuoteToASCII(target))
		if entry.Info != nil {
			if entry.Info.Caller != nil {
				c := entry.Info.Caller
				fmt.Fprintf(os.Stdout, " caller=%s client=%s", strconv.QuoteToASCII(c.Host), strconv.QuoteToASCII(c.ClientName))
			}
			if entry.Info.Reason != "" {
				fmt.Fprintf(os.Stdout, " reason=%s", strconv.QuoteToASCII(entry.Info.Reason))
			}
		}
		if entry.ExitCode != nil {
			fmt.Fprintf(os.Stdout, " exit=%d duration=%s", *entry.ExitCode, entry.Duration.Round(time.Millisecond))
		}
		fmt.Fprintln(os.Stdout)
	}
	for _, lease := range response.Leases {
		fmt.Fprintf(os.Stdout, "  lease %s remaining=%d expires=%s scope=%s\n", lease.ID, lease.Remaining, lease.Expires.Format(time.RFC3339), strconv.QuoteToASCII(lease.Scope))
	}
	keys := make([]string, 0, len(response.SignatureUses))
	for key := range response.SignatureUses {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(os.Stdout, "  signatures %s used=%d\n", key, response.SignatureUses[key])
	}
	if response.HistoryError != "" {
		fmt.Fprintln(os.Stdout, "  "+response.HistoryError)
	}
}

func explain(args []string) (int, error) {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	config := fs.String("config", "", "policy file")
	profile := fs.String("profile", "", "policy profile")
	home, _ := os.UserHomeDir()
	directory := fs.String("dir", home, "local working directory")
	reason := fs.String("reason", "", "request reason")
	key := fs.String("key", "", "explain SSH key use by fingerprint")
	purpose := fs.String("purpose", "ssh", "SSH signing purpose")
	namespace := fs.String("namespace", "", "SSHSIG namespace")
	operation := fs.String("operation", "", "explain an SSH management operation")
	provider := fs.String("provider", "", "provider identifier for management")
	topic := fs.String("topic", "", "explain an approval request topic")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if *config == "" {
		return 2, errors.New("explain requires --config")
	}
	p, err := policy.LoadProfile(*config, *profile)
	if err != nil {
		return 2, err
	}
	result := policy.Explanation{}
	switch {
	case *topic != "":
		if fs.NArg() != 0 {
			return 2, errors.New("topic explanation takes no command")
		}
		result.Approval, err = p.AuthorizeApproval(*topic)
		result.Allowed = err == nil
	case *operation != "":
		if fs.NArg() != 0 {
			return 2, errors.New("management explanation takes no command")
		}
		result.Approval, err = p.AuthorizeManagement(sshagent.ManagementRequest{Operation: *operation, Fingerprint: *key, Provider: *provider})
		result.Allowed = err == nil
	case *key != "":
		if fs.NArg() != 0 {
			return 2, errors.New("key explanation takes no command")
		}
		var rule policy.KeyRule
		rule, err = p.AuthorizeSSH(sshagent.SigningRequest{Fingerprint: *key, Purpose: *purpose, Namespace: *namespace})
		result.Approval = rule.Approval
		result.Lease = rule.Lease
		result.Allowed = err == nil
	default:
		if fs.NArg() == 0 {
			return 2, errors.New("explain requires a command, --key, --operation, or --topic")
		}
		result = p.Explain(*directory, protocol.Request{Args: fs.Args(), Reason: *reason})
	}
	if err != nil {
		result.Error = err.Error()
	}
	slices.Sort(result.CredentialVariables)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 1, err
	}
	if !result.Allowed {
		return 1, nil
	}
	return 0, nil
}
