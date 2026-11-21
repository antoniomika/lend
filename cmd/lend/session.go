package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/antoniomika/lend/internal/policy"
)

func connect(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	config := fs.String("config", "", "local policy file")
	profile := fs.String("profile", "", "independent policy profile")
	upstream := fs.String("upstream", os.Getenv("SSH_AUTH_SOCK"), "original agent socket")
	mode := fs.String("approval", "auto", "auto or terminal")
	home, _ := os.UserHomeDir()
	directory := fs.String("dir", home, "local working directory")
	approvalTimeout := fs.Duration("approval-timeout", time.Minute, "queue and approval timeout")
	commandTimeout := fs.Duration("command-timeout", 5*time.Minute, "credential retrieval and command timeout")
	silent := fs.Bool("silent", false, "hide lend startup messages (errors and approval prompts remain visible)")
	systemAgent := fs.Bool("system-agent", false, "use the original agent for login while forwarding lend's proxy")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: lend ssh [LEND OPTIONS] [SSH OPTIONS] [--] HOST [COMMAND...]")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), "Lend options must precede SSH arguments. Environment defaults: LEND_CONFIG, LEND_PROFILE,\nLEND_UPSTREAM, LEND_DIR, LEND_APPROVAL, LEND_APPROVAL_TIMEOUT, LEND_COMMAND_TIMEOUT,\nLEND_SILENT, LEND_SYSTEM_AGENT.")
		fmt.Fprintln(fs.Output(), "A -- ends SSH option parsing. Put SSH options before it.")
	}
	sshArgs, err := parseSSHFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	label, local, err := inspectSSHArgs(sshArgs)
	if err != nil {
		return 2, err
	}
	if local || label == "" {
		return runSSH(ctx, sshArgs, "", "")
	}
	if err := applyEnvDefaults(fs); err != nil {
		return 2, err
	}
	if *config == "" {
		return 2, errors.New("ssh requires --config FILE or LEND_CONFIG")
	}
	if *approvalTimeout <= 0 || *commandTimeout <= 0 {
		return 2, errors.New("timeouts must be positive")
	}
	if _, err := policy.LoadProfile(*config, *profile); err != nil {
		return 2, err
	}
	root, err := filepath.Abs(filepath.Dir(defaultSocket()))
	if err != nil {
		return 1, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return 1, err
	}
	runtimeDir, err := os.MkdirTemp(root, "session-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(runtimeDir)
	socket := filepath.Join(runtimeDir, "agent.sock")
	executable, err := os.Executable()
	if err != nil {
		return 1, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer reader.Close()
	defer writer.Close()
	lifetimeReader, lifetimeWriter, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer lifetimeReader.Close()
	defer lifetimeWriter.Close()
	if *profile != "" {
		label = *profile + "@" + label
	}
	childArgs := []string{"agent", "--config", *config, "--socket", socket, "--upstream", *upstream, "--approval", *mode, "--session", label, "--_ready-fd", "3", "--_lifetime-fd", "4"}
	childArgs = append(childArgs, "--approval-timeout", approvalTimeout.String(), "--command-timeout", commandTimeout.String())
	childArgs = append(childArgs, "--silent="+strconv.FormatBool(*silent))
	childArgs = append(childArgs, "--profile", *profile)
	childArgs = append(childArgs, "--dir", *directory)
	child := exec.Command(executable, childArgs...)
	child.ExtraFiles = []*os.File{writer, lifetimeReader}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return 1, err
	}
	writer.Close()
	lifetimeReader.Close()
	childDone := make(chan struct{})
	go func() { child.Wait(); close(childDone) }()
	defer func() {
		child.Process.Signal(syscall.SIGTERM)
		select {
		case <-childDone:
		case <-time.After(5 * time.Second):
			child.Process.Kill()
			<-childDone
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(reader).ReadString('\n')
		ready <- err == nil && line == "ready\n"
	}()
	select {
	case ok := <-ready:
		if !ok {
			return 1, errors.New("session agent failed to start")
		}
	case <-ctx.Done():
		return 1, ctx.Err()
	case <-time.After(10 * time.Second):
		return 1, errors.New("session agent startup timed out")
	}
	if !*silent {
		fmt.Fprintf(os.Stderr, "lend session %q\nInspect with: lend status --socket %q\n", label, socket)
	}
	sshCtx, cancelSSH := context.WithCancel(ctx)
	defer cancelSSH()
	go func() {
		select {
		case <-childDone:
			cancelSSH()
		case <-sshCtx.Done():
		}
	}()
	authSocket := socket
	if *systemAgent {
		authSocket = *upstream
	}
	code, err := runSSH(sshCtx, sessionSSHArgs(sshArgs), authSocket, socket)
	select {
	case <-childDone:
		return 1, errors.New("session agent stopped while SSH was running")
	default:
	}
	return code, err
}

func runSSH(ctx context.Context, args []string, authSocket, forwardSocket string) (int, error) {
	command := exec.CommandContext(ctx, "ssh", args...)
	if authSocket != "" {
		command.Env = append(os.Environ(), "SSH_AUTH_SOCK="+authSocket, "_LEND_SESSION_SOCKET="+forwardSocket)
	}
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code := exit.ExitCode()
			if code < 0 {
				code = 125
			}
			return code, nil
		}
		return 1, err
	}
	return 0, nil
}

func sessionSSHArgs(args []string) []string {
	// Environment expansion preserves literal tokens in the socket path.
	result := []string{"-A", "-o", "IdentityAgent=SSH_AUTH_SOCK", "-o", "ForwardAgent=${_LEND_SESSION_SOCKET}", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ForkAfterAuthentication=no", "-o", "ExitOnForwardFailure=yes"}
	return append(result, args...)
}
