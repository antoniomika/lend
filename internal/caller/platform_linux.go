package caller

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

func process(_ context.Context, pid int) string {
	if pid <= 0 {
		return ""
	}
	path, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return path
}

func socketPeer(fd int) *Peer {
	cred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || cred.Pid <= 0 {
		return nil
	}
	return &Peer{PID: int(cred.Pid), UID: &cred.Uid}
}
