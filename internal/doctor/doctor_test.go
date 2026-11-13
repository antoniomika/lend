package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

func TestProbeOnlyRequestsExtensionDiscovery(t *testing.T) {
	valid := protocol.ExtensionPacket(protocol.ExtensionResponse, "query", sshagent.String([]byte(protocol.Extension)))
	for _, test := range []struct {
		name             string
		reply            []byte
		supported, valid bool
	}{
		{"lend", valid, true, true},
		{"plain-agent", []byte{5}, false, true},
		{"extension-refused", []byte{28}, false, true},
		{"wrong-response", protocol.ExtensionPacket(29, "other", nil), false, false},
		{"truncated-list", protocol.ExtensionPacket(29, "query", []byte{0, 0, 0, 9, 'a'}), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				request, err := protocol.Read(server)
				if err != nil {
					t.Error(err)
					return
				}
				name, data, err := protocol.ParseExtension(request)
				if err != nil || request[0] != 27 || name != "query" || len(data) != 0 {
					t.Error("doctor requested more than extension discovery")
				}
				protocol.Write(server, test.reply)
			}()
			supported, err := probeConn(context.Background(), client, time.Second)
			<-done
			if supported != test.supported || (err == nil) != test.valid {
				t.Fatalf("supported=%t err=%v", supported, err)
			}
		})
	}
}

func TestProbeHonorsTimeoutAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		client, server := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		}
		start := time.Now()
		_, err := probeConn(ctx, client, 20*time.Millisecond)
		cancel()
		client.Close()
		server.Close()
		if err == nil || time.Since(start) > time.Second {
			t.Fatal("socket probe did not stop")
		}
	}
}

func TestDoctorDoesNotExecuteConfiguredToolsOrReadCredentials(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "executed")
	tool := filepath.Join(directory, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(directory, "policy.json")
	data := `{"secret_reader":` + quote(tool) + `,"commands":[{"executable":` + quote(tool) + `,"approval":"prompt","secrets":{"TOKEN":"op://vault/item/field"}}]}`
	if err := os.WriteFile(config, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), Options{Config: config, Socket: filepath.Join(directory, "missing", "agent.sock"), Upstream: filepath.Join(directory, "absent"), Directory: directory, Approval: "terminal", Timeout: 20 * time.Millisecond})
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("doctor executed a configured program")
	}
	if !hasCheck(report, "policy", "ok") || !hasCheck(report, "executable", "ok") {
		t.Fatalf("policy was not inspected: %+v", report)
	}
	for _, check := range report.Checks {
		if strings.Contains(check.Message, "op://") {
			t.Fatal("doctor printed credential references")
		}
	}
}

func TestApprovalRequirementsOnlyApplyToAdmittedDefaults(t *testing.T) {
	p, err := policy.Parse([]byte(`{"default":"deny","default_approval":"biometric","ssh":{"default":"deny","default_approval":"biometric","management":{"default":"deny","default_approval":"biometric"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	backend := "fixture"
	if runtime.GOOS == "darwin" {
		backend = "macOS"
	}
	support := approval.Support{Backend: backend, Prompt: true}
	report := Report{}
	checkApproval(&report, p, "auto", support)
	if !report.Healthy() {
		t.Fatal("denied defaults required authentication")
	}
	p.Default = "allow"
	checkApproval(&report, p, "auto", support)
	if !hasCheck(report, "biometrics", "error") {
		t.Fatal("required biometrics were not checked")
	}
}

func TestSocketAndHistoryChecksDoNotCreatePaths(t *testing.T) {
	directory := t.TempDir()
	socket := filepath.Join(directory, "new", "agent.sock")
	history := filepath.Join(directory, "history", "records.jsonl")
	report := Report{}
	checkSocketDirectory(&report, socket)
	checkHistory(&report, history)
	if _, err := os.Stat(filepath.Dir(socket)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("doctor created a socket directory")
	}
	if _, err := os.Stat(filepath.Dir(history)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("doctor created a history directory")
	}
	os.Chmod(directory, 0755)
	report = Report{}
	checkSocketDirectory(&report, filepath.Join(directory, "agent.sock"))
	if !hasCheck(report, "socket-directory", "error") {
		t.Fatal("public socket directory accepted")
	}
}

func TestRemoteDoctorRequiresTheProxy(t *testing.T) {
	report := Run(context.Background(), Options{Remote: true, Socket: filepath.Join(t.TempDir(), "missing"), Timeout: 20 * time.Millisecond})
	if report.Healthy() || len(report.Checks) != 1 || report.Mode != "remote" {
		t.Fatalf("incorrect remote report: %+v", report)
	}
}

func hasCheck(report Report, name, status string) bool {
	for _, check := range report.Checks {
		if check.Name == name && check.Status == status {
			return true
		}
	}
	return false
}
func quote(s string) string { data, _ := json.Marshal(s); return string(data) }

func TestUnpromptedRulesAreReported(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(policy.Policy{Commands: []policy.Rule{{Executable: path, ArgsPrefix: []string{"pr", "view"}, Approval: "none"}}})
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	report := Report{}
	checkApproval(&report, p, "terminal", approval.Support{})
	if !hasCheck(report, "unprompted", "warn") {
		t.Fatalf("%+v", report.Checks)
	}
	open, err := policy.Parse([]byte(`{"default":"allow","default_approval":"none"}`))
	if err != nil {
		t.Fatal(err)
	}
	report = Report{}
	checkApproval(&report, open, "terminal", approval.Support{})
	if !hasCheck(report, "unprompted", "warn") {
		t.Fatalf("%+v", report.Checks)
	}
}

func TestApprovalBackendOnlyRequiredForPromptedOperations(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := `"executable":` + quote(path)
	key := `"fingerprint":` + quote(sshagent.Fingerprint([]byte("fixture")))
	for _, test := range []struct {
		name           string
		config         string
		requiresPrompt bool
	}{
		{"no config", "", true},
		{"deny all", `{}`, false},
		{"command default", `{"default":"allow","default_approval":"none"}`, false},
		{"SSH default", `{"ssh":{"default":"allow","default_approval":"none"}}`, false},
		{"management default", `{"ssh":{"management":{"default":"allow","default_approval":"none"}}}`, false},
		{"command rule", `{"commands":[{` + command + `,"approval":"none"}]}`, false},
		{"SSH rule", `{"ssh":{"keys":[{` + key + `,"approval":"none"}]}}`, false},
		{"management rule", `{"ssh":{"management":{"operations":[{"operation":"lock","approval":"none"}]}}}`, false},
		{"prompted command", `{"default":"allow","default_approval":"none","commands":[{` + command + `,"approval":"prompt"}]}`, true},
		{"prompted SSH", `{"default":"allow","default_approval":"none","ssh":{"keys":[{` + key + `,"approval":"auto"}]}}`, true},
		{"prompted management", `{"default":"allow","default_approval":"none","ssh":{"management":{"operations":[{"operation":"lock","approval":"prompt"}]}}}`, true},
		{"prompted default", `{"default":"allow","commands":[{` + command + `,"approval":"none"}]}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var p *policy.Policy
			if test.config != "" {
				var err error
				p, err = policy.Parse([]byte(test.config))
				if err != nil {
					t.Fatal(err)
				}
			}
			report := Report{}
			checkApproval(&report, p, "auto", approval.Support{})
			if hasCheck(report, "approval-backend", "error") != test.requiresPrompt || report.Healthy() == test.requiresPrompt {
				t.Fatalf("requiresPrompt=%t checks=%+v", test.requiresPrompt, report.Checks)
			}
			if strings.Contains(test.config, `"none"`) && !hasCheck(report, "unprompted", "warn") {
				t.Fatalf("missing unprompted warning: %+v", report.Checks)
			}
		})
	}
}

func TestBiometricStylesRequireBiometrics(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, approvalValue := range []string{"biometric", "biometric:inline", "biometric:separate"} {
		p, err := policy.Parse([]byte(`{"commands":[{"executable":` + quote(path) + `,"approval":` + quote(approvalValue) + `}]}`))
		if err != nil {
			t.Fatal(err)
		}
		report := Report{}
		checkApproval(&report, p, "auto", approval.Support{Backend: "macOS", Prompt: true, Authentication: true})
		if !hasCheck(report, "biometrics", "error") {
			t.Fatalf("%s did not check biometrics: %+v", approvalValue, report.Checks)
		}
	}
}
