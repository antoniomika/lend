package activity

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
)

func TestHistoryPersistsDecisionsWithoutRequestSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "history.jsonl")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	store := New(journal, false)
	ctx, id, err := store.Begin(context.Background(), "connection", "development", "command", approval.Summary{Executable: "/usr/bin/tool", Args: []string{"tool", "secret-argument"}, Reason: "secret-reason", Credentials: map[string]string{"TOKEN": "op://secret-vault/item/field"}})
	if err != nil {
		t.Fatal(err)
	}
	store.Describe(id, approval.Summary{Executable: "/usr/bin/tool", Requirement: "biometric"})
	store.Decision(id, "once")
	store.Stage(id, "running")
	status := 7
	store.Finish(id, "completed", &status)
	if ctx.Err() == nil {
		t.Fatal("finished activity context is still live")
	}
	journal.Close()
	offline, err := ReadHistory(path)
	if err != nil || len(offline) != 1 || offline[0].Approval != "once" {
		t.Fatalf("offline history: %+v %v", offline, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"secret-argument", "secret-reason", "TOKEN", "op://"} {
		if bytes.Contains(data, []byte(value)) {
			t.Fatalf("history leaked %s", value)
		}
	}
	again, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	records := New(again, false).Snapshot(true).History
	if len(records) != 1 || records[0].ExitCode == nil || *records[0].ExitCode != 7 || records[0].Approval != "once" || records[0].Requirement != "biometric" || records[0].Duration <= 0 {
		t.Fatalf("history lost completion: %+v", records)
	}
}

func TestHistoryReaderIgnoresOnlyAnIncompleteFinalRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	if err := os.WriteFile(path, []byte("{\"id\":\"complete\",\"kind\":\"command\"}\n{\"id\":\"incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	records, err := ReadHistory(path)
	if err != nil || len(records) != 1 || records[0].ID != "complete" {
		t.Fatalf("%+v %v", records, err)
	}
	os.WriteFile(path, []byte("invalid\n"), 0600)
	if _, err := ReadHistory(path); err == nil {
		t.Fatal("corrupt complete record accepted")
	}
}

func TestPauseAndRevocationCancelActivities(t *testing.T) {
	store := New(nil, false)
	ctx, id, err := store.Begin(context.Background(), "", "", "connection", approval.Summary{})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := store.Begin(ctx, id, "", "command", approval.Summary{})
	if err != nil {
		t.Fatal(err)
	}
	if !store.Revoke(id) || ctx.Err() == nil || child.Err() == nil {
		t.Fatal("revocation did not cancel descendants")
	}
	store.Pause(true)
	if _, _, err := store.Begin(context.Background(), "", "", "command", approval.Summary{}); err == nil {
		t.Fatal("paused store accepted activity")
	}
	store.Pause(false)
	if _, _, err := store.Begin(context.Background(), "", "", "command", approval.Summary{}); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryBoundsAndArgumentOptIn(t *testing.T) {
	store := New(nil, true)
	for range 300 {
		_, id, err := store.Begin(context.Background(), "", "", "command", approval.Summary{Args: []string{"tool", "public-argument"}})
		if err != nil {
			t.Fatal(err)
		}
		store.Finish(id, "denied", nil)
	}
	snapshot := store.Snapshot(true)
	if len(snapshot.History) != 256 || len(snapshot.Active) != 0 || len(snapshot.History[0].Args) != 2 || snapshot.History[0].Info != nil {
		t.Fatal("history was not bounded or argument opt-in failed")
	}
}

func TestJournalRejectsPublicFilesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "history")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	if journal, err := OpenJournal(path); err == nil {
		journal.Close()
		t.Fatal("public history accepted")
	}
	os.Remove(path)
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte{}, 0600)
	os.Symlink(target, path)
	if journal, err := OpenJournal(path); err == nil {
		journal.Close()
		t.Fatal("history symlink accepted")
	}
	os.Remove(path)
	os.Chmod(dir, 0755)
	if journal, err := OpenJournal(path); err == nil {
		journal.Close()
		t.Fatal("public history directory accepted")
	}
}

func TestSharedJournalWritersSurviveRotation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "history")
	first, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.file.Truncate(maxJournal - 1); err != nil {
		t.Fatal(err)
	}
	for i, journal := range []*Journal{first, second} {
		if err := journal.Append(Entry{ID: []string{"first", "second"}[i], Kind: "command", Started: time.Now().UTC(), State: "completed"}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("lost a writer after rotation: %q", data)
	}
	for i, line := range lines {
		var record Entry
		if err := json.Unmarshal(line, &record); err != nil || record.ID != []string{"first", "second"}[i] {
			t.Fatal("rotated history changed records")
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("rotation did not preserve previous file")
	}
}
