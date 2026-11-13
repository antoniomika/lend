package caller

import (
	"context"
	"net"
	"os"
	"os/user"
	"strings"
	"unicode/utf8"

	"github.com/antoniomika/lend/internal/protocol"
)

func Capture(ctx context.Context, source string) protocol.Caller {
	uid := uint32(os.Getuid())
	c := protocol.Caller{Source: source, UID: &uid, PID: os.Getpid(), ParentPID: os.Getppid()}
	c.Host, _ = os.Hostname()
	if current, err := user.Current(); err == nil {
		c.User = current.Username
	}
	c.Executable, _ = os.Executable()
	c.Directory, _ = os.Getwd()
	c.ParentProcess = process(ctx, c.ParentPID)
	c.SSHConnection = os.Getenv("SSH_CONNECTION")
	for _, field := range []struct {
		value *string
		max   int
	}{
		{&c.Host, 256}, {&c.User, 256}, {&c.Executable, 4096}, {&c.Directory, 4096}, {&c.ParentProcess, 4096}, {&c.SSHConnection, 512},
	} {
		if len(*field.value) > field.max || !utf8.ValidString(*field.value) || strings.ContainsRune(*field.value, 0) {
			*field.value = ""
		}
	}
	return c
}

type Peer struct {
	PID     int
	UID     *uint32
	Process string
}

func LocalPeer(ctx context.Context, conn net.Conn) *Peer {
	connection, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil
	}
	var peer *Peer
	if err := raw.Control(func(fd uintptr) { peer = socketPeer(int(fd)) }); err != nil {
		return nil
	}
	if peer != nil && peer.PID > 0 {
		peer.Process = process(ctx, peer.PID)
	}
	return peer
}
