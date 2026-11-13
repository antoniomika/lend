package client

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func ListKeys(ctx context.Context, socket string) ([]sshagent.Identity, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := protocol.Write(conn, []byte{sshagent.RequestIdentities}); err != nil {
		return nil, err
	}
	p, err := protocol.Read(conn)
	if err != nil {
		return nil, err
	}
	if len(p) == 1 && p[0] == protocol.AgentFailure {
		return nil, errors.New("agent refused to list keys")
	}
	return sshagent.ParseIdentities(p)
}
