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
	"strings"
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
	directory := fs.String("dir", "", "local working directory")
	approvalTimeout := fs.Duration("approval-timeout", time.Minute, "queue and approval timeout")
	commandTimeout := fs.Duration("command-timeout", 5*time.Minute, "credential retrieval and command timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, err
	}
	if *config == "" || fs.NArg() == 0 || strings.HasPrefix(fs.Arg(0), "-") {
		return 2, errors.New("ssh requires --config FILE and -- HOST [COMMAND...]; configure SSH options in ~/.ssh/config")
	}
	if *approvalTimeout <= 0 || *commandTimeout <= 0 {
		return 2, errors.New("timeouts must be positive")
	}
	if _, err := policy.LoadProfile(*config, *profile); err != nil {
		return 2, err
	}
	root := filepath.Dir(defaultSocket())
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
	label := fs.Arg(0)
	if *profile != "" {
		label = *profile + "@" + label
	}
	childArgs := []string{"agent", "--config", *config, "--socket", socket, "--upstream", *upstream, "--approval", *mode, "--session", label, "--_ready-fd", "3", "--_lifetime-fd", "4"}
	childArgs = append(childArgs, "--approval-timeout", approvalTimeout.String(), "--command-timeout", commandTimeout.String())
	if *profile != "" {
		childArgs = append(childArgs, "--profile", *profile)
	}
	if *directory != "" {
		childArgs = append(childArgs, "--dir", *directory)
	}
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
	fmt.Fprintf(os.Stderr, "lend session %q\nInspect with: lend status --socket %q\n", label, socket)
	sshCtx, cancelSSH := context.WithCancel(ctx)
	defer cancelSSH()
	go func() {
		select {
		case <-childDone:
			cancelSSH()
		case <-sshCtx.Done():
		}
	}()
	command := exec.CommandContext(sshCtx, "ssh", sessionSSHArgs(fs.Args())...)
	command.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err = command.Run()
	select {
	case <-childDone:
		return 1, errors.New("session agent stopped while SSH was running")
	default:
	}
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
	result := []string{"-A", "-o", "IdentityAgent=SSH_AUTH_SOCK", "-o", "ForwardAgent=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ForkAfterAuthentication=no", "-o", "ExitOnForwardFailure=yes", "--"}
	return append(result, args...)
}
