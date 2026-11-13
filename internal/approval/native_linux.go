package approval

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

func native(ctx context.Context, s Summary) error {
	_, err := nativeDecision(ctx, s)
	return err
}

func nativeDecision(ctx context.Context, s Summary) (Decision, error) {
	if s.Requirement == "authenticate" || s.Requirement == "biometric" {
		return Decision{}, errors.New("required device authentication is unavailable on Linux")
	}
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		if path, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.CommandContext(ctx, path, "--text-info", "--filename=/dev/stdin", "--title=lend: local approval", "--width=720", "--height=500", "--font=Monospace 11", "--checkbox=I have reviewed this request and approval scope", "--ok-label=Allow once", "--cancel-label=Deny")
			cmd.Stdin = strings.NewReader(s.String())
			for _, entry := range os.Environ() {
				name, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(name, "ZENITY_") && !strings.HasPrefix(name, "DIALOG_") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "ZENITY_OK=0", "ZENITY_CANCEL=1", "ZENITY_ESC=1", "ZENITY_EXTRA=2", "ZENITY_ERROR=3", "ZENITY_TIMEOUT=5")
			var choice bytes.Buffer
			cmd.Stdout = &choice
			if s.Lease != nil {
				cmd.Args = append(cmd.Args, "--extra-button=Allow lease")
			}
			err := cmd.Run()
			if ctx.Err() != nil {
				return Decision{}, ctx.Err()
			}
			selected := strings.TrimSpace(choice.String())
			var exit *exec.ExitError
			if s.Lease != nil && selected == "Allow lease" && errors.As(err, &exit) && exit.ExitCode() == 2 {
				return Decision{Lease: true}, nil
			}
			if err != nil || selected != "" {
				return Decision{}, errors.New("desktop approval denied or unavailable")
			}
			return Decision{}, nil
		}
	}
	return terminalDecision(ctx, s)
}

func RunHelper() int { return 1 }
