package approval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestNativeHelperDecisions(t *testing.T) {
	for _, tc := range []struct {
		name         string
		scenario     string
		leaseOffered bool
		wantAllowed  bool
		wantLease    bool
	}{
		{name: "once", scenario: "once", wantAllowed: true},
		{name: "once with lease offered", scenario: "once", leaseOffered: true, wantAllowed: true},
		{name: "lease", scenario: "lease", leaseOffered: true, wantAllowed: true, wantLease: true},
		{name: "unoffered lease", scenario: "lease"},
		{name: "deny", scenario: "deny", leaseOffered: true},
		{name: "normal quit", scenario: "quit", leaseOffered: true},
		{name: "exit two", scenario: "exit-two", leaseOffered: true},
		{name: "panic", scenario: "panic", leaseOffered: true},
		{name: "signal", scenario: "signal", leaseOffered: true},
		{name: "failed after decision", scenario: "failed-after-decision", leaseOffered: true},
		{name: "truncated decision", scenario: "truncated"},
		{name: "extra output", scenario: "extra"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			decision, err := runNativeHelper(ctx, nativeHelperCommand(ctx, tc.scenario), tc.leaseOffered)
			if (err == nil) != tc.wantAllowed || decision.Lease != tc.wantLease {
				t.Fatalf("decision=%+v err=%v", decision, err)
			}
		})
	}
}

func TestNativeHelperCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := runNativeHelper(ctx, nativeHelperCommand(ctx, "lease"), true)
	if !errors.Is(err, context.Canceled) || decision.Lease {
		t.Fatalf("cancelled helper returned decision=%+v err=%v", decision, err)
	}
}

func TestNativeHelperDecisionWriteFailure(t *testing.T) {
	r, w := io.Pipe()
	r.Close()
	defer w.Close()
	if code := writeNativeHelperDecision(w, 1); code == 0 {
		t.Fatal("failed decision write returned success")
	}
	var output bytes.Buffer
	if code := writeNativeHelperDecision(&output, 0); code == 0 || output.Len() != 0 {
		t.Fatalf("denial wrote %q with exit code %d", output.String(), code)
	}
}

func nativeHelperCommand(ctx context.Context, scenario string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeHelperProcess$", "--", scenario)
	cmd.Env = append(os.Environ(), "LEND_TEST_NATIVE_HELPER=1")
	return cmd
}

func TestNativeHelperProcess(t *testing.T) {
	if os.Getenv("LEND_TEST_NATIVE_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "once":
		os.Exit(writeNativeHelperDecision(os.Stdout, 1))
	case "lease":
		os.Exit(writeNativeHelperDecision(os.Stdout, 2))
	case "deny":
		os.Exit(writeNativeHelperDecision(os.Stdout, 0))
	case "quit":
		os.Exit(0)
	case "exit-two":
		os.Exit(2)
	case "panic":
		panic("native helper failure")
	case "signal":
		syscall.Kill(os.Getpid(), syscall.SIGKILL)
	case "failed-after-decision":
		writeNativeHelperDecision(os.Stdout, 2)
		os.Exit(2)
	case "truncated":
		fmt.Fprint(os.Stdout, "lend-approval:once")
		os.Exit(0)
	case "extra":
		writeNativeHelperDecision(os.Stdout, 1)
		fmt.Fprint(os.Stdout, "unexpected output\n")
		os.Exit(0)
	}
	os.Exit(1)
}
