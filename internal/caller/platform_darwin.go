package caller

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func process(parent context.Context, pid int) string {
	if pid <= 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(parent, 250*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	cmd.WaitDelay = 50 * time.Millisecond
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func socketPeer(fd int) *Peer {
	// Darwin exposes the connecting process ID through SOL_LOCAL / LOCAL_PEERPID.
	pid, err := syscall.GetsockoptInt(fd, 0, 2)
	if err != nil || pid <= 0 {
		return nil
	}
	return &Peer{PID: pid}
}
