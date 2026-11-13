package activity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/antoniomika/lend/internal/approval"
)

type Entry struct {
	ID          string            `json:"id"`
	Parent      string            `json:"connection,omitempty"`
	Session     string            `json:"session,omitempty"`
	Kind        string            `json:"kind"`
	State       string            `json:"state"`
	Approval    string            `json:"approval,omitempty"`
	Requirement string            `json:"requirement,omitempty"`
	Executable  string            `json:"executable,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Operation   string            `json:"operation,omitempty"`
	Topic       string            `json:"topic,omitempty"`
	Started     time.Time         `json:"started"`
	Finished    time.Time         `json:"finished,omitempty"`
	Duration    time.Duration     `json:"duration,omitempty"`
	ExitCode    *int              `json:"exit_code,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Info        *approval.Summary `json:"info,omitempty"`
}

type running struct {
	entry  Entry
	cancel context.CancelFunc
}

type Snapshot struct {
	Paused       bool    `json:"paused"`
	Active       []Entry `json:"active"`
	History      []Entry `json:"history,omitempty"`
	HistoryError string  `json:"history_error,omitempty"`
}

type Store struct {
	mu           sync.Mutex
	paused       bool
	active       map[string]running
	history      []Entry
	journal      *Journal
	logArguments bool
	historyError string
}

func New(journal *Journal, logArguments bool) *Store {
	s := &Store{active: make(map[string]running), journal: journal, logArguments: logArguments}
	if journal != nil {
		s.history = append(s.history, journal.Previous...)
	}
	return s
}

func (s *Store) Begin(parent context.Context, connection, session, kind string, summary approval.Summary) (context.Context, string, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", err
	}
	id := hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused {
		cancel()
		return nil, "", errors.New("lend is paused")
	}
	entry := Entry{ID: id, Parent: connection, Session: session, Kind: kind, State: "connected", Started: time.Now().UTC(), Executable: summary.Executable, Fingerprint: summary.KeyFingerprint, Topic: summary.Topic}
	if kind != "connection" {
		entry.State = "checking"
		entry.Info = &summary
	}
	if summary.Management != nil {
		entry.Operation = summary.Management.Operation
		entry.Fingerprint = summary.Management.Fingerprint
	}
	if s.logArguments {
		entry.Args = append([]string(nil), summary.Args...)
	}
	s.active[id] = running{entry: entry, cancel: cancel}
	return ctx, id, nil
}

func (s *Store) Stage(id, stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.active[id]; ok {
		r.entry.State = stage
		s.active[id] = r
	}
}

func (s *Store) Describe(id string, summary approval.Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.active[id]; ok {
		r.entry.Info = &summary
		r.entry.Requirement = summary.Requirement
		r.entry.Executable = summary.Executable
		if s.logArguments {
			r.entry.Args = append([]string(nil), summary.Args...)
		}
		s.active[id] = r
	}
}

func (s *Store) Decision(id, decision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.active[id]; ok {
		r.entry.Approval = decision
		s.active[id] = r
	}
}

func (s *Store) Finish(id, state string, code *int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.active[id]
	if !ok {
		return
	}
	delete(s.active, id)
	r.cancel()
	if r.entry.Kind == "connection" {
		return
	}
	r.entry.State = state
	r.entry.Info = nil
	r.entry.Finished = time.Now().UTC()
	r.entry.Duration = r.entry.Finished.Sub(r.entry.Started)
	if code != nil {
		value := *code
		r.entry.ExitCode = &value
	}
	s.history = append(s.history, r.entry)
	if len(s.history) > 256 {
		s.history = append([]Entry(nil), s.history[len(s.history)-256:]...)
	}
	if s.journal != nil {
		if err := s.journal.Append(r.entry); err != nil {
			s.historyError = "could not append local history"
		}
	}
}

func (s *Store) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.active[id]
	if ok {
		r.cancel()
	}
	return ok
}

func (s *Store) Pause(paused bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paused = paused
	if paused {
		for _, r := range s.active {
			r.cancel()
		}
	}
}

func (s *Store) Snapshot(history bool) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{Paused: s.paused, Active: make([]Entry, 0, len(s.active)), HistoryError: s.historyError}
	for _, r := range s.active {
		out.Active = append(out.Active, r.entry)
	}
	if history {
		out.History = append([]Entry(nil), s.history...)
	}
	return out
}
