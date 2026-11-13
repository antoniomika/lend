package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/sshagent"
)

func (s *Server) approve(parent context.Context, summary approval.Summary) error {
	ctx, cancel := context.WithTimeout(parent, s.ApprovalTimeout)
	defer cancel()
	summary.Session = s.Session
	if id, ok := ctx.Value(requestID{}).(string); ok {
		summary.RequestID = id
		s.Activity.Describe(id, summary)
	}
	s.stage(ctx, "queued")
	select {
	case s.approvals <- struct{}{}:
		defer func() { <-s.approvals }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !s.SessionBound {
		summary.Lease = nil
	}
	if summary.Lease != nil {
		if !s.unlocked(ctx) {
			summary.Lease = nil
		} else if s.consumeLease(summary) {
			s.stage(ctx, "leased")
			if summary.RequestID != "" {
				s.Activity.Decision(summary.RequestID, "lease")
			}
			return ctx.Err()
		}
	}
	s.leaseMu.Lock()
	generation := s.leaseGeneration
	s.leaseMu.Unlock()
	if summary.RequestID != "" {
		s.Activity.Describe(summary.RequestID, summary)
	}
	s.stage(ctx, "approval")
	var decision approval.Decision
	var err error
	if s.Decide != nil {
		decision, err = s.Decide(ctx, summary)
	} else {
		err = s.Approve(ctx, summary)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil && decision.Lease && summary.Lease != nil && s.unlocked(ctx) {
		s.grantLease(summary, generation)
	}
	if summary.RequestID != "" {
		result := "denied"
		if err == nil {
			result = "once"
			if decision.Lease && summary.Lease != nil {
				result = "lease-approved"
			}
		}
		s.Activity.Decision(summary.RequestID, result)
	}
	return err
}

func (s *Server) sign(parent context.Context, conn net.Conn, packet []byte, info connectionInfo, exchange func([]byte) ([]byte, error)) ([]byte, error) {
	failure := []byte{5}
	request, err := sshagent.ParseSign(packet)
	if err != nil {
		return failure, nil
	}
	ctx, done, err := s.begin(parent, info, info.summary(signingSummary(request, policy.KeyRule{})))
	if err != nil {
		return failure, nil
	}
	outcome := "denied"
	defer func() { done(outcome, nil) }()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	key, err := s.Policy.AuthorizeSSH(request)
	if err != nil {
		return failure, nil
	}
	finish, err := s.reserveSignature(key)
	if err != nil {
		return failure, nil
	}
	success := false
	defer func() { finish(success) }()
	conn.SetDeadline(time.Now().Add(s.ApprovalTimeout + 5*time.Second))
	summary := info.summary(signingSummary(request, key))
	summary.Lease = leaseOffer(key.Lease, signingLeaseScope(summary))
	if err := s.approve(ctx, summary); err != nil {
		outcome = refusalOutcome(ctx, err)
		return failure, nil
	}
	s.stage(ctx, "upstream")
	outcome = "upstream-error"
	reply, err := exchange(packet)
	if err != nil {
		return failure, err
	}
	if err := sshagent.ValidateSignature(reply); err != nil {
		return failure, err
	}
	success = reply[0] == sshagent.SignResponse
	outcome = "upstream-refused"
	if success {
		outcome = "completed"
	}
	return reply, nil
}

func (s *Server) reserveSignature(key policy.KeyRule) (func(bool), error) {
	if key.MaxSignatures == 0 {
		return func(bool) {}, nil
	}
	s.signMu.Lock()
	defer s.signMu.Unlock()
	if s.signUses == nil {
		s.signUses = make(map[string]int)
	}
	if s.signUses[key.Fingerprint] >= key.MaxSignatures {
		return nil, errors.New("SSH key signature limit reached")
	}
	s.signUses[key.Fingerprint]++
	return func(success bool) {
		if !success {
			s.signMu.Lock()
			s.signUses[key.Fingerprint]--
			s.signMu.Unlock()
		}
	}, nil
}

func signingSummary(request sshagent.SigningRequest, key policy.KeyRule) approval.Summary {
	digest := sha256.Sum256(request.Data)
	return approval.Summary{
		Kind: "ssh-sign", Requirement: key.Approval, KeyFingerprint: request.Fingerprint,
		KeyType: request.KeyType, KeyLabel: key.Label, SigningPurpose: request.Purpose,
		SigningNamespace: request.Namespace, SigningBytes: len(request.Data), SigningFlags: request.Flags,
		SigningDigest: "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]),
	}
}
