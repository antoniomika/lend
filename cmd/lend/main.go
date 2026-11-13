package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/antoniomika/lend/internal/activity"
	"github.com/antoniomika/lend/internal/agent"
	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/control"
	"github.com/antoniomika/lend/internal/mcp"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "_approve" {
		os.Exit(approval.RunHelper())
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code, err := run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "lend:", err)
	}
	os.Exit(code)
}

func defaultSocket() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "lend", "agent.sock")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lend", "agent.sock")
}

func run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		usage()
		return 2, nil
	}
	switch args[0] {
	case "doctor":
		return diagnose(ctx, args[1:])
	case "version", "--version":
		return versionCommand(args[1:])
	case "agent":
		return serve(ctx, args[1:])
	case "ssh":
		return connect(ctx, args[1:])
	case "status", "history", "pause", "resume", "revoke", "clear-leases":
		return administer(ctx, args[0], args[1:])
	case "explain":
		return explain(args[1:])
	case "keys":
		fs := flag.NewFlagSet("keys", flag.ContinueOnError)
		socket := fs.String("socket", os.Getenv("SSH_AUTH_SOCK"), "SSH agent socket to inspect")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0, nil
			}
			return 2, err
		}
		if fs.NArg() != 0 || *socket == "" {
			return 2, errors.New("keys requires an agent socket and takes no positional arguments")
		}
		ids, err := client.ListKeys(ctx, *socket)
		if err != nil {
			return 1, err
		}
		for _, id := range ids {
			kind, _ := sshagent.KeyType(id.Blob)
			fmt.Fprintf(os.Stdout, "%s %s %s\n", sshagent.Fingerprint(id.Blob), strconv.QuoteToASCII(kind), strconv.QuoteToASCII(string(id.Comment)))
		}
		return 0, nil
	case "exec":
		fs := flag.NewFlagSet("exec", flag.ContinueOnError)
		socket := fs.String("socket", os.Getenv("SSH_AUTH_SOCK"), "forwarded agent socket")
		reason := fs.String("reason", "", "why this command is needed (shown in the local approval prompt)")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0, nil
			}
			return 2, err
		}
		if fs.NArg() == 0 {
			return 2, errors.New("expected a command after exec --")
		}
		if *socket == "" {
			return 2, errors.New("SSH_AUTH_SOCK is unset; use --socket")
		}
		var stdin io.Reader = os.Stdin
		if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			stdin = &emptyReader{}
		}
		who := caller.Capture(ctx, "cli")
		return client.RunRequest(ctx, *socket, protocol.Request{Args: fs.Args(), Reason: *reason, Caller: &who}, stdin, os.Stdout, os.Stderr)
	case "mcp":
		fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
		socket := fs.String("socket", os.Getenv("SSH_AUTH_SOCK"), "forwarded agent socket")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0, nil
			}
			return 2, err
		}
		if fs.NArg() != 0 || *socket == "" {
			return 2, errors.New("mcp requires an agent socket and takes no positional arguments")
		}
		server := mcp.Server{Run: func(ctx context.Context, request protocol.Request, input io.Reader, out, stderr io.Writer) (int, error) {
			return client.RunRequest(ctx, *socket, request, input, out, stderr)
		}}
		if err := server.Serve(ctx, os.Stdin, os.Stdout); err != nil {
			return 1, err
		}
		return 0, nil
	case "help", "--help", "-h":
		usage()
		return 0, nil
	default:
		return 2, fmt.Errorf("unknown command %q", args[0])
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func serve(ctx context.Context, args []string) (int, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 1, err
	}
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	socket := fs.String("socket", defaultSocket(), "local proxy socket (inside a private directory)")
	upstream := fs.String("upstream", os.Getenv("SSH_AUTH_SOCK"), "original SSH agent socket")
	dir := fs.String("dir", home, "local working directory for all commands")
	mode := fs.String("approval", "auto", "approval mode: auto or terminal")
	config := fs.String("config", "", "local JSON command policy file")
	profile := fs.String("profile", "", "independent named policy profile")
	session := fs.String("session", "", "local session label shown during approval")
	readyFD := fs.Int("_ready-fd", -1, "internal readiness pipe")
	lifetimeFD := fs.Int("_lifetime-fd", -1, "internal parent lifetime pipe")
	allowAll := fs.Bool("allow-all", false, "allow commands, SSH signing, and supported agent management, with approval for each operation")
	approvalTimeout := fs.Duration("approval-timeout", time.Minute, "time allowed for local approval")
	commandTimeout := fs.Duration("command-timeout", 5*time.Minute, "maximum command runtime")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage of %s:\n", fs.Name())
		visible := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
		visible.SetOutput(fs.Output())
		fs.VisitAll(func(f *flag.Flag) {
			if len(f.Name) > 0 && f.Name[0] == '_' {
				return
			}
			visible.Var(f.Value, f.Name, f.Usage)
			visible.Lookup(f.Name).DefValue = f.DefValue
		})
		visible.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if fs.NArg() != 0 {
		return 2, errors.New("agent takes no positional arguments")
	}
	if *approvalTimeout <= 0 || *commandTimeout <= 0 {
		return 2, errors.New("timeouts must be positive")
	}
	if (*config == "" && !*allowAll) || (*config != "" && *allowAll) {
		return 2, errors.New("choose exactly one of --config FILE or --allow-all")
	}
	p := policy.AllowAll()
	if *profile != "" && *config == "" {
		return 2, errors.New("--profile requires --config")
	}
	if len(*session) > 256 {
		return 2, errors.New("session label exceeds 256 bytes")
	}
	if *config != "" {
		p, err = policy.LoadProfile(*config, *profile)
		if err != nil {
			return 2, fmt.Errorf("load policy: %w", err)
		}
	}
	decide, err := approval.NewDecider(*mode)
	if err != nil {
		return 2, err
	}
	*socket, err = filepath.Abs(*socket)
	if err != nil {
		return 2, err
	}
	*dir, err = filepath.Abs(*dir)
	if err != nil {
		return 2, err
	}
	info, err := os.Stat(*dir)
	if err != nil {
		return 2, err
	}
	if !info.IsDir() {
		return 2, errors.New("--dir must be a directory")
	}
	if *upstream == "" {
		return 2, errors.New("original SSH_AUTH_SOCK is unset; start ssh-agent or use --upstream")
	}
	*upstream, err = filepath.Abs(*upstream)
	if err != nil {
		return 2, err
	}
	if *socket == *upstream {
		return 2, errors.New("proxy and upstream sockets must differ")
	}
	// Resolve existing aliases before opening the proxy to prevent forwarding loops.
	if existing, err := filepath.EvalSymlinks(*upstream); err == nil && existing == *socket {
		return 2, errors.New("upstream points to the proxy socket")
	}
	probe, err := os.Stat(*upstream)
	if err != nil {
		return 2, err
	}
	if probe.Mode()&os.ModeSocket == 0 {
		return 2, errors.New("upstream must be a Unix socket")
	}
	listener, err := agent.Listen(*socket)
	if err != nil {
		return 1, err
	}
	defer listener.Close()
	controlListener, err := agent.Listen(*socket + ".control")
	if err != nil {
		return 1, err
	}
	defer controlListener.Close()
	var journal *activity.Journal
	if p.History.Path != "" {
		journal, err = activity.OpenJournal(p.History.Path)
		if err != nil {
			return 1, fmt.Errorf("open history: %w", err)
		}
		defer journal.Close()
	}
	if *session == "" {
		*session = *profile
	}
	fmt.Fprintf(os.Stderr, "lend agent listening on %s\n", *socket)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if *lifetimeFD >= 3 {
		syscall.CloseOnExec(*lifetimeFD)
		lifetime := os.NewFile(uintptr(*lifetimeFD), "lend-parent")
		if lifetime == nil {
			return 1, errors.New("invalid parent lifetime pipe")
		}
		defer lifetime.Close()
		go func() { io.Copy(io.Discard, lifetime); cancel() }()
	}
	s := &agent.Server{Socket: *socket, Upstream: *upstream, Directory: *dir, Decide: decide, Activity: activity.New(journal, p.History.LogArguments), Session: *session, SessionBound: *lifetimeFD >= 3, Policy: p, ApprovalTimeout: *approvalTimeout, CommandTimeout: *commandTimeout}
	controlDone := make(chan error, 1)
	go func() { err := control.Serve(ctx, controlListener, s.Control); controlDone <- err; cancel() }()
	defer func() { cancel(); controlListener.Close(); <-controlDone }()
	if *readyFD >= 3 {
		ready := os.NewFile(uintptr(*readyFD), "lend-ready")
		if ready == nil {
			return 1, errors.New("invalid readiness pipe")
		}
		_, err = io.WriteString(ready, "ready\n")
		ready.Close()
		if err != nil {
			return 1, err
		}
	}
	if err := s.Serve(ctx, listener); err != nil {
		return 1, err
	}
	return 0, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  lend agent (--config FILE | --allow-all) [--socket PATH] [--upstream PATH]
  lend exec [--socket PATH] [--reason TEXT] -- COMMAND [ARG...]
  lend mcp [--socket PATH]
  lend keys [--socket PATH]
  lend ssh --config FILE [--profile NAME] -- HOST [COMMAND...]
  lend status [--socket PATH | --all] [--watch] [--json]
  lend history [--socket PATH | --all | --file PATH] [--json]
  lend pause|resume|clear-leases [--socket PATH | --all]
  lend revoke [--socket PATH] ID
  lend explain --config FILE [--profile NAME] -- COMMAND [ARG...]
  lend doctor [--config FILE] [--profile NAME] [--json]
  lend doctor --remote [--socket PATH]
  lend version [--json]

Run the agent on your laptop, forward its socket with SSH agent forwarding,
then run lend exec on the remote host. Commands, SSH signatures, and agent management require local approval.
Use a subcommand's --help for all options.`)
}
