package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"
)

type secretBuffer struct{ bytes.Buffer }

func (b *secretBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 64*1024 {
		return 0, errors.New("credential exceeds size limit")
	}
	return b.Buffer.Write(data)
}

func (s *Server) commandEnvironment(ctx context.Context, references map[string]string) ([]string, error) {
	values := make(map[string]string)
	if s.Socket != "" {
		values["SSH_AUTH_SOCK"] = s.Socket
	}
	environment := replaceEnvironment(os.Environ(), values)
	names := make([]string, 0, len(references))
	for name := range references {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if s.Policy.SecretReader == "" {
			return nil, errors.New("credential reader is not configured")
		}
		cmd := exec.CommandContext(ctx, s.Policy.SecretReader, "read", "--no-newline", references[name])
		cmd.Env = environment
		cmd.Dir = s.Directory
		cmd.Stderr = io.Discard
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		var output secretBuffer
		cmd.Stdout = &output
		err := cmd.Run()
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		if err != nil || bytes.IndexByte(output.Bytes(), 0) >= 0 {
			clear(output.Bytes())
			clear(values)
			return nil, errors.New("could not retrieve local credential")
		}
		values[name] = string(output.Bytes())
		clear(output.Bytes())
	}
	result := replaceEnvironment(environment, values)
	clear(values)
	return result, nil
}

func replaceEnvironment(environment []string, values map[string]string) []string {
	result := make([]string, 0, len(environment)+len(values))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if _, ok := values[name]; !ok {
			result = append(result, entry)
		}
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}
