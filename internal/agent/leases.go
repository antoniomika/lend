package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/control"
	"github.com/antoniomika/lend/internal/device"
	"github.com/antoniomika/lend/internal/policy"
)

type grant struct {
	control.Lease
}

func leaseOffer(lease *policy.Lease, scope string) *approval.LeaseOffer {
	if lease == nil {
		return nil
	}
	return &approval.LeaseOffer{Duration: lease.Duration, Uses: lease.Uses, Scope: scope}
}

func leaseKey(summary approval.Summary) string {
	data, _ := json.Marshal([]any{summary.Kind, summary.Session, summary.Requirement, summary.Executable, summary.Args, summary.Directory, summary.Credentials, summary.KeyFingerprint, summary.SigningPurpose, summary.SigningNamespace, summary.SigningFlags, summary.Peer, summary.Bindings})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (s *Server) clearLeases(id string) {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	s.leaseGeneration++
	if id == "" {
		s.leases = nil
		return
	}
	for key, value := range s.leases {
		if value.ID == id {
			delete(s.leases, key)
		}
	}
}

func (s *Server) leaseViews() []control.Lease {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	result := make([]control.Lease, 0, len(s.leases))
	for key, value := range s.leases {
		if !time.Now().Before(value.Expires) || value.Remaining <= 0 {
			delete(s.leases, key)
			continue
		}
		result = append(result, value.Lease)
	}
	return result
}

func (s *Server) unlocked(ctx context.Context) bool {
	s.deviceMu.Lock()
	defer s.deviceMu.Unlock()
	check := s.DeviceCheck
	if check == nil {
		check = device.Check
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	state, err := check(checkCtx)
	s.deviceStatus = "unlocked"
	if err != nil {
		s.deviceStatus = "unavailable"
	} else if !state.Unlocked {
		s.deviceStatus = "locked-or-inactive"
	}
	if err != nil || !state.Unlocked || state.Changed {
		s.clearLeases("")
	}
	return err == nil && state.Unlocked
}

func (s *Server) WatchDevice(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.clearLeases("")
			return
		case <-ticker.C:
			s.unlocked(ctx)
		}
	}
}

func (s *Server) consumeLease(summary approval.Summary) bool {
	key := leaseKey(summary)
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	value, ok := s.leases[key]
	if !ok || !time.Now().Before(value.Expires) || value.Remaining < 1 {
		delete(s.leases, key)
		return false
	}
	value.Remaining--
	s.leases[key] = value
	return true
}

func (s *Server) grantLease(summary approval.Summary, generation uint64) {
	duration, err := time.ParseDuration(summary.Lease.Duration)
	if err != nil || duration <= 0 || duration > time.Hour || summary.Lease.Uses < 1 || summary.Lease.Uses > 100 {
		return
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return
	}
	key := leaseKey(summary)
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	if generation != s.leaseGeneration {
		return
	}
	if s.leases == nil {
		s.leases = make(map[string]grant)
	}
	for key, value := range s.leases {
		if !time.Now().Before(value.Expires) || value.Remaining <= 0 {
			delete(s.leases, key)
		}
	}
	if len(s.leases) >= 128 {
		return
	}
	s.leases[key] = grant{Lease: control.Lease{ID: hex.EncodeToString(nonce[:]), Scope: summary.Lease.Scope, Expires: time.Now().Add(duration), Remaining: summary.Lease.Uses - 1}}
}

func signingLeaseScope(summary approval.Summary) string {
	return fmt.Sprintf("key %s, purpose %s, namespace %q", summary.KeyFingerprint, summary.SigningPurpose, summary.SigningNamespace)
}
