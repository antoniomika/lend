package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func Listen(path string) (*net.UnixListener, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("socket directory must be owned by you and have mode 0700: %s", parent)
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return nil, fmt.Errorf("socket path already exists or cannot be inspected: %s", path)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
