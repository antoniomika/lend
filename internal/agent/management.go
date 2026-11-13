package agent

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/sshagent"
)

func (s *Server) manage(ctx context.Context, conn net.Conn, packet []byte, info connectionInfo, exchange func([]byte) ([]byte, error)) ([]byte, error) {
	// Management messages can contain private keys, passphrases, or PINs.
	defer clear(packet)
	failure := []byte{5}
	request, err := sshagent.ParseManagement(packet)
	if err != nil {
		return failure, nil
	}
	ctx, done, err := s.begin(ctx, info, info.summary(approval.Summary{Kind: "ssh-manage", Management: &request}))
	if err != nil {
		return failure, nil
	}
	outcome := "denied"
	defer func() { done(outcome, nil) }()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	requirement, err := s.Policy.AuthorizeManagement(request)
	if err != nil {
		return failure, nil
	}
	conn.SetDeadline(time.Now().Add(s.ApprovalTimeout + 5*time.Second))
	if err := s.approve(ctx, info.summary(approval.Summary{Kind: "ssh-manage", Requirement: requirement, Management: &request})); err != nil {
		outcome = refusalOutcome(ctx, err)
		return failure, nil
	}
	s.stage(ctx, "upstream")
	outcome = "upstream-error"
	reply, err := exchange(packet)
	if err != nil {
		return failure, err
	}
	if len(reply) != 1 || (reply[0] != 5 && reply[0] != 6) {
		return failure, errors.New("invalid management response")
	}
	outcome = "upstream-refused"
	if reply[0] == 6 {
		outcome = "completed"
		s.clearLeases("")
	}
	return reply, nil
}
