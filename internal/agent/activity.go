package agent

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/antoniomika/lend/internal/activity"
	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/control"
)

type requestID struct{}

func refusalOutcome(ctx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "expired"
	}
	if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return "cancelled"
	}
	return "denied"
}

func (s *Server) initActivity() {
	s.initOnce.Do(func() {
		if s.Activity == nil {
			s.Activity = activity.New(nil, false)
		}
	})
}

func (s *Server) begin(parent context.Context, info connectionInfo, summary approval.Summary) (context.Context, func(string, *int), error) {
	s.initActivity()
	kind := summary.Kind
	if kind == "" {
		kind = "command"
	}
	ctx, id, err := s.Activity.Begin(parent, info.id, s.Session, kind, summary)
	if err != nil {
		return nil, nil, err
	}
	ctx = context.WithValue(ctx, requestID{}, id)
	var once sync.Once
	return ctx, func(state string, code *int) { once.Do(func() { s.Activity.Finish(id, state, code) }) }, nil
}

func (s *Server) stage(ctx context.Context, state string) {
	if id, ok := ctx.Value(requestID{}).(string); ok {
		s.Activity.Stage(id, state)
	}
}

func (s *Server) Control(request control.Request) control.Response {
	s.initActivity()
	response := control.Response{Session: s.Session, PID: os.Getpid()}
	switch request.Action {
	case "status", "history":
	case "pause":
		s.Activity.Pause(true)
		s.clearLeases("")
	case "resume":
		s.Activity.Pause(false)
	case "revoke":
		// Revoking any activity invalidates leases that may have authorized it.
		s.clearLeases("")
		if !s.Activity.Revoke(request.ID) {
			response.Error = "activity ID does not exist"
		}
	case "clear-leases":
		s.clearLeases(request.ID)
	default:
		response.Error = "unknown local control action"
	}
	response.Snapshot = s.Activity.Snapshot(request.Action == "history")
	response.Leases = s.leaseViews()
	s.deviceMu.Lock()
	response.LeaseTracking = s.deviceStatus
	s.deviceMu.Unlock()
	if response.LeaseTracking == "" {
		response.LeaseTracking = "pending"
	}
	if !s.SessionBound {
		response.LeaseTracking = "session-supervision-required"
	} else if s.Policy != nil && !s.Policy.HasLeases() {
		response.LeaseTracking = "disabled"
	}
	s.signMu.Lock()
	response.SignatureUses = make(map[string]int, len(s.signUses))
	for key, uses := range s.signUses {
		response.SignatureUses[key] = uses
	}
	s.signMu.Unlock()
	return response
}
