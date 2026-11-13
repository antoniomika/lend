package agent

import (
	"context"
	"net"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/protocol"
)

func (s *Server) requestApproval(ctx context.Context, conn net.Conn, data []byte, info connectionInfo) []byte {
	failure := []byte{protocol.ExtensionFailure}
	request, err := protocol.DecodeApproval(data)
	if err != nil {
		return failure
	}
	summary := info.summary(approval.Summary{Kind: "approval", Topic: request.Topic, Title: request.Title, Details: request.Details, Reason: request.Reason, Caller: request.Caller})
	ctx, done, err := s.begin(ctx, info, summary)
	if err != nil {
		return failure
	}
	outcome := "denied"
	defer func() { done(outcome, nil) }()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	requirement, err := s.Policy.AuthorizeApproval(request.Topic)
	if err != nil {
		return failure
	}
	conn.SetDeadline(time.Now().Add(s.ApprovalTimeout + 5*time.Second))
	summary.Requirement = requirement
	if err := s.approve(ctx, summary); err != nil {
		outcome = refusalOutcome(ctx, err)
		return failure
	}
	outcome = "approved"
	return []byte{protocol.AgentSuccess}
}
