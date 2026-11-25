package approval

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

const (
	nativeHelperOnce  = "lend-approval:once\n"
	nativeHelperLease = "lend-approval:lease\n"
)

func runNativeHelper(ctx context.Context, cmd *exec.Cmd, leaseOffered bool) (Decision, error) {
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return Decision{}, ctx.Err()
	}
	// AppKit termination and runtime failures can use the same exit codes as normal returns.
	if err == nil {
		switch string(output) {
		case nativeHelperOnce:
			return Decision{}, nil
		case nativeHelperLease:
			if leaseOffered {
				return Decision{Lease: true}, nil
			}
		}
	}
	return Decision{}, errors.New("local approval denied or authentication failed")
}

func writeNativeHelperDecision(w io.Writer, result int) int {
	var token string
	switch result {
	case 1:
		token = nativeHelperOnce
	case 2:
		token = nativeHelperLease
	default:
		return 1
	}
	n, err := io.WriteString(w, token)
	if err != nil || n != len(token) {
		return 1
	}
	return 0
}
