package client

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/protocol"
)

// ErrDenied means the laptop refused the request: policy, denial, or an expired prompt.
var ErrDenied = errors.New("approval refused: policy, denial, or timeout")

func Approve(ctx context.Context, socket string, request protocol.ApprovalRequest) error {
	if request.Caller == nil {
		who := caller.Capture(ctx, "client")
		request.Caller = &who
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	return ApproveConn(ctx, conn, request)
}

func ApproveConn(ctx context.Context, conn net.Conn, request protocol.ApprovalRequest) error {
	defer conn.Close()
	packet, err := protocol.EncodeApproval(request)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := protocol.Write(conn, packet); err != nil {
		return err
	}
	// Revocation and pause close the connection, so losing it after sending is a refusal.
	reply, err := protocol.Read(conn)
	if err != nil {
		return fmt.Errorf("%w: connection closed before a decision", ErrDenied)
	}
	switch {
	case len(reply) == 1 && reply[0] == protocol.AgentSuccess:
		return nil
	case len(reply) == 1 && reply[0] == protocol.ExtensionFailure:
		return ErrDenied
	case len(reply) == 1 && reply[0] == protocol.AgentFailure:
		return errors.New("agent does not support lend approvals; forward a current lend agent socket")
	}
	return errors.New("invalid approval response")
}
