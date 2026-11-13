package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/client"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

type testAgent struct {
	server *Server
	ctx    context.Context
	wg     sync.WaitGroup
}

func startServer(t *testing.T, approve approval.Approver, upstream string, timeout time.Duration) (*testAgent, string) {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	h := &testAgent{ctx: ctx, server: &Server{Upstream: upstream, Directory: dir, Approve: approve, Policy: policy.AllowAll(), ApprovalTimeout: time.Second, CommandTimeout: timeout, approvals: make(chan struct{}, 1)}}
	h.server.initActivity()
	h.server.SessionBound = true
	t.Cleanup(func() { cancel(); h.wg.Wait() })
	return h, dir
}

func (h *testAgent) dial() net.Conn {
	clientConn, serverConn := net.Pipe()
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer serverConn.Close()
		stop := context.AfterFunc(h.ctx, func() { serverConn.Close() })
		defer stop()
		h.server.handle(h.ctx, serverConn)
	}()
	return clientConn
}

func (h *testAgent) run(ctx context.Context, args []string, input io.Reader, stdout, stderr io.Writer) (int, error) {
	return client.RunConn(ctx, h.dial(), args, input, stdout, stderr)
}

func allow(context.Context, approval.Summary) error { return nil }

func TestStreamsAndApprovalDetails(t *testing.T) {
	var approved approval.Summary
	socket, dir := startServer(t, func(_ context.Context, s approval.Summary) error { approved = s; return nil }, "", 5*time.Second)
	input := strings.Repeat("hello\x00world\n", 10000)
	var stdout, stderr bytes.Buffer
	args := []string{"sh", "-c", "cat; printf 'stderr' >&2; exit 7"}
	code, err := socket.run(context.Background(), args, strings.NewReader(input), &stdout, &stderr)
	if err != nil || code != 7 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if stdout.String() != input || stderr.String() != "stderr" {
		t.Fatal("stream data changed")
	}
	if !filepath.IsAbs(approved.Executable) || approved.Directory != dir || strings.Join(approved.Args, "\x00") != strings.Join(args, "\x00") {
		t.Fatalf("wrong approval: %+v", approved)
	}
}

func TestDeniedRequestDoesNotExecute(t *testing.T) {
	socket, dir := startServer(t, func(context.Context, approval.Summary) error { return errors.New("denied") }, "", time.Second)
	marker := filepath.Join(dir, "must-not-exist")
	_, err := socket.run(context.Background(), []string{"touch", marker}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("denial was ignored")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("denied command ran")
	}
}

func TestPolicyRejectsBeforePrompt(t *testing.T) {
	var prompts atomic.Int32
	socket, dir := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	socket.server.Policy = &policy.Policy{Default: "deny"}
	marker := filepath.Join(dir, "must-not-exist")
	_, err := socket.run(context.Background(), []string{"touch", marker}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || prompts.Load() != 0 {
		t.Fatal("unlisted command reached approval")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unlisted command executed")
	}
}

func TestPolicyRequirementAndReasonReachApproval(t *testing.T) {
	var summary approval.Summary
	socket, _ := startServer(t, func(_ context.Context, s approval.Summary) error { summary = s; return nil }, "", time.Second)
	path, err := exec.LookPath("printf")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(policy.Policy{RequireReason: true, Commands: []policy.Rule{{Executable: path, ArgsPrefix: []string{"%s"}, Approval: "biometric"}}})
	socket.server.Policy, err = policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	request := protocol.Request{Args: []string{"printf", "%s", "hello"}, Reason: "inspect local output", Caller: &protocol.Caller{Source: "cli", Host: "agent-vm", User: "user", PID: 123, Directory: "/work/project"}}
	code, err := client.RunRequestConn(context.Background(), socket.dial(), request, strings.NewReader(""), &out, io.Discard)
	if err != nil || code != 0 || out.String() != "hello" {
		t.Fatalf("%d %v %q", code, err, out.String())
	}
	if summary.Reason != request.Reason || summary.Requirement != "biometric" {
		t.Fatalf("approval lost policy or reason: %+v", summary)
	}
	if summary.Caller == nil || *summary.Caller != *request.Caller {
		t.Fatal("caller context was lost in transit")
	}
}

func TestDisconnectCancelsApproval(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	socket, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}, "", time.Second)
	conn := socket.dial()
	packet, _ := protocol.EncodeRequest(protocol.Request{Args: []string{"true"}})
	if err := protocol.Write(conn, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no approval")
	}
	conn.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("approval survived disconnect")
	}
}

func TestMalformedRequestDoesNotPrompt(t *testing.T) {
	var prompts atomic.Int32
	socket, _ := startServer(t, func(context.Context, approval.Summary) error { prompts.Add(1); return nil }, "", time.Second)
	for _, payload := range []string{`{"args":[]}`, `{"args":["true"],"env":{"PATH":"/bad"}}`, `{"args":["true"]} {}`, `{"args":["a\u0000b"]}`} {
		conn := socket.dial()
		conn.SetDeadline(time.Now().Add(time.Second))
		if err := protocol.Write(conn, protocol.ExtensionPacket(protocol.AgentExtension, protocol.Extension, []byte(payload))); err != nil {
			t.Fatal(err)
		}
		p, err := protocol.Read(conn)
		conn.Close()
		if err != nil || !bytes.Equal(p, []byte{protocol.ExtensionFailure}) {
			t.Fatalf("%s: %v %v", payload, p, err)
		}
	}
	if prompts.Load() != 0 {
		t.Fatal("invalid command prompted")
	}
}

func TestProxyPreservesConnectionState(t *testing.T) {
	upstreamClient, upstreamServer := net.Pipe()
	defer upstreamClient.Close()
	defer upstreamServer.Close()
	done := make(chan error, 1)
	bind := sessionBinding(testKey(1))
	requests := [][]byte{bind, {sshagent.RequestIdentities}, signPacket(testKey(1), []byte("data"))}
	replies := [][]byte{{6}, sshagent.EncodeIdentities(nil), signature([]byte("data"))}
	go func() {
		conn := upstreamServer
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		for i, want := range requests {
			packet, err := protocol.Read(conn)
			if err != nil {
				done <- err
				return
			}
			if !bytes.Equal(packet, want) {
				done <- errors.New("upstream request changed")
				return
			}
			if err := protocol.Write(conn, replies[i]); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	socket, _ := startServer(t, allow, "", time.Second)
	socket.server.dialUpstream = func(context.Context) (net.Conn, error) { return upstreamClient, nil }
	conn := socket.dial()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	for i, packet := range requests {
		if err := protocol.Write(conn, packet); err != nil {
			t.Fatal(err)
		}
		p, err := protocol.Read(conn)
		if err != nil || !bytes.Equal(p, replies[i]) {
			t.Fatalf("proxy: %v %v", p, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutStopsCommand(t *testing.T) {
	socket, _ := startServer(t, allow, "", 100*time.Millisecond)
	start := time.Now()
	_, err := socket.run(context.Background(), []string{"sleep", "10"}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("timeout was ignored")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("command was not interrupted")
	}
}

func TestExpiredApprovalDoesNotExecute(t *testing.T) {
	socket, dir := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		<-ctx.Done()
		return nil
	}, "", time.Second)
	socket.server.ApprovalTimeout = 50 * time.Millisecond
	marker := filepath.Join(dir, "must-not-exist")
	_, err := socket.run(context.Background(), []string{"touch", marker}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expired approval was accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("command ran after expiry")
	}
}

func TestApprovalQueueSerializesCommands(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var prompts atomic.Int32
	socket, _ := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		prompts.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, "", time.Second)
	done := make(chan error, 2)
	run := func() {
		_, err := socket.run(context.Background(), []string{"true"}, strings.NewReader(""), io.Discard, io.Discard)
		done <- err
	}
	go run()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no approval")
	}
	go run()
	waitStage(t, socket.server, "queued", 1)
	if prompts.Load() != 1 {
		t.Fatal("multiple approval dialogs opened")
	}
	release <- struct{}{}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("queued request did not reach approval")
	}
	release <- struct{}{}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

type pidWriter struct{ pid chan int }

func (w pidWriter) Write(p []byte) (int, error) {
	pid, err := strconv.Atoi(string(p))
	if err != nil {
		return 0, err
	}
	w.pid <- pid
	return len(p), nil
}

func TestDisconnectKillsCommand(t *testing.T) {
	socket, _ := startServer(t, allow, "", 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pids := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		_, err := socket.run(ctx, []string{"sh", "-c", "printf '%s' $$; exec sleep 10"}, strings.NewReader(""), pidWriter{pid: pids}, io.Discard)
		done <- err
	}()
	var pid int
	select {
	case pid = <-pids:
	case <-time.After(2 * time.Second):
		t.Fatal("command did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled client succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not cancel")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command survived disconnection")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRejectInputBeforeApproval(t *testing.T) {
	entered := make(chan struct{})
	socket, dir := startServer(t, func(ctx context.Context, _ approval.Summary) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}, "", time.Second)
	conn := socket.dial()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	marker := filepath.Join(dir, "must-not-exist")
	packet, _ := protocol.EncodeRequest(protocol.Request{Args: []string{"touch", marker}})
	if err := protocol.Write(conn, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no approval")
	}
	if err := protocol.Write(conn, []byte{protocol.Stdin, 'x'}); err != nil {
		t.Fatal(err)
	}
	p, err := protocol.Read(conn)
	if err != nil || !bytes.Equal(p, []byte{protocol.ExtensionFailure}) {
		t.Fatalf("early input accepted: %v %v", p, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("command ran before approval")
	}
}

func TestArgvIsNotInterpretedByShell(t *testing.T) {
	socket, dir := startServer(t, allow, "", time.Second)
	argument := "$(touch " + filepath.Join(dir, "must-not-exist") + ")"
	var out bytes.Buffer
	code, err := socket.run(context.Background(), []string{"printf", "%s", argument}, strings.NewReader(""), &out, io.Discard)
	if err != nil || code != 0 || out.String() != argument {
		t.Fatalf("code=%d err=%v output=%q", code, err, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "must-not-exist")); !os.IsNotExist(err) {
		t.Fatal("shell expanded argv")
	}
}

func TestPrivateSocketDirectory(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0755)
	if l, err := Listen(filepath.Join(dir, "agent.sock")); err == nil {
		l.Close()
		t.Fatal("accepted shared directory")
	}
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "agent.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(path); err == nil {
		l.Close()
		t.Fatal("overwrote existing file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatal("existing file changed")
	}
}

func TestOpenSSHAgentPassthrough(t *testing.T) {
	path, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent unavailable")
	}
	dir := t.TempDir()
	probe, err := net.Listen("unix", filepath.Join(dir, "p"))
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("Unix sockets blocked by environment: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	upstream := filepath.Join(dir, "a")
	cmd := exec.Command(path, "-D", "-a", upstream)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(upstream); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ssh-agent did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	socket, _ := startServer(t, allow, upstream, time.Second)
	conn := socket.dial()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if err := protocol.Write(conn, []byte{11}); err != nil {
		t.Fatal(err)
	}
	reply, err := protocol.Read(conn)
	if err != nil || len(reply) != 5 || reply[0] != 12 || binary.BigEndian.Uint32(reply[1:]) != 0 {
		t.Fatalf("ssh-agent identities: %v %v", reply, err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	add := []byte{17}
	for _, field := range [][]byte{[]byte("ssh-ed25519"), private.Public().(ed25519.PublicKey), private, []byte("fixture")} {
		add = append(add, sshagent.String(field)...)
	}
	direct, err := net.Dial("unix", upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if p := roundTrip(t, direct, add); !bytes.Equal(p, []byte{6}) {
		t.Fatalf("isolated agent could not load fixture: %v", p)
	}
	if p := roundTrip(t, conn, signPacket(testKey(1), []byte("data"))); !bytes.Equal(p, signature([]byte("data"))) {
		t.Fatal("isolated OpenSSH agent signature differs")
	}
	if p := roundTrip(t, conn, managementPacket(18, testKey(1))); !bytes.Equal(p, []byte{6}) {
		t.Fatal("proxy could not remove isolated fixture")
	}
	if p := roundTrip(t, conn, addFixture()); !bytes.Equal(p, []byte{6}) {
		t.Fatal("proxy could not add isolated fixture")
	}
	if p := roundTrip(t, conn, managementPacket(22, []byte("fixture-passphrase"))); !bytes.Equal(p, []byte{6}) {
		t.Fatal("proxy could not lock isolated agent")
	}
	if p := roundTrip(t, conn, managementPacket(23, []byte("fixture-passphrase"))); !bytes.Equal(p, []byte{6}) {
		t.Fatal("proxy could not unlock isolated agent")
	}
	if p := roundTrip(t, conn, []byte{19}); !bytes.Equal(p, []byte{6}) {
		t.Fatal("proxy could not clear isolated agent")
	}
}

func TestUnixListenerExecutionAndShutdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s")
	l, err := Listen(socket)
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("Unix sockets blocked by environment: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	s := &Server{Directory: dir, Approve: allow, Policy: policy.AllowAll(), ApprovalTimeout: time.Second, CommandTimeout: time.Second}
	go func() { done <- s.Serve(ctx, l) }()
	var out bytes.Buffer
	code, err := client.Run(context.Background(), socket, []string{"printf", "hello"}, strings.NewReader(""), &out, io.Discard)
	if err != nil || code != 0 || out.String() != "hello" {
		t.Fatalf("Unix execution: %d %v %q", code, err, out.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not stop")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("socket was not removed")
	}
}

func TestMatchedRuleSetsArgv0(t *testing.T) {
	var prompted []string
	h, _ := startServer(t, func(_ context.Context, s approval.Summary) error {
		prompted = s.Args
		return nil
	}, "", 5*time.Second)
	t.Setenv("LEND_TEST_PRINT_ARGV0", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	target, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	allowed, other := filepath.Join(dir, "allowed"), filepath.Join(dir, "other")
	for _, alias := range []string{allowed, other} {
		if err := os.Symlink(target, alias); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := json.Marshal(policy.Policy{Commands: []policy.Rule{{Executable: allowed, Approval: "prompt"}}})
	h.server.Policy, err = policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code, err := h.run(context.Background(), []string{other, "-test.run=^TestPrintArgv0Fixture$"}, strings.NewReader(""), &out, io.Discard)
	if err != nil || code != 0 || out.String() != allowed {
		t.Fatalf("code=%d err=%v argv0=%q", code, err, out.String())
	}
	if len(prompted) == 0 || prompted[0] != allowed {
		t.Fatalf("prompt showed %q", prompted)
	}
}

func TestMatchedRuleArgv0WithConcurrentActivityReads(t *testing.T) {
	h, _ := startServer(t, func(context.Context, approval.Summary) error {
		return errors.New("denied")
	}, "", time.Second)
	path, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(policy.Policy{Commands: []policy.Rule{{Executable: path, Approval: "prompt"}}})
	h.server.Policy, err = policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if _, err := json.Marshal(h.server.Activity.Snapshot(false)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	defer func() { cancel(); <-done }()
	for i := 0; i < 200; i++ {
		if _, err := h.run(context.Background(), []string{"true"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("denied command succeeded")
		}
	}
}

// TestPrintArgv0Fixture runs as the approved command and reports the argv[0] it received.
func TestPrintArgv0Fixture(t *testing.T) {
	if os.Getenv("LEND_TEST_PRINT_ARGV0") == "" {
		t.Skip("subprocess fixture")
	}
	os.Stdout.WriteString(os.Args[0])
	os.Exit(0)
}

func TestUnpromptedRuleSkipsApproval(t *testing.T) {
	var prompts atomic.Int32
	h, _ := startServer(t, func(context.Context, approval.Summary) error {
		prompts.Add(1)
		return nil
	}, "", time.Second)
	path, err := exec.LookPath("printf")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(policy.Policy{Commands: []policy.Rule{
		{Executable: path, Approval: "prompt"},
		{Executable: path, ArgsPrefix: []string{"unprompted"}, Approval: "none"},
	}})
	h.server.Policy, err = policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		arg     string
		prompts int32
	}{{"unprompted", 0}, {"prompted", 1}} {
		var out bytes.Buffer
		code, err := h.run(context.Background(), []string{"printf", tc.arg}, strings.NewReader(""), &out, io.Discard)
		if err != nil || code != 0 || out.String() != tc.arg || prompts.Load() != tc.prompts {
			t.Fatalf("%s: code=%d err=%v out=%q prompts=%d", tc.arg, code, err, out.String(), prompts.Load())
		}
	}
	waitHistory(t, h.server, 2)
	decisions := map[string]bool{}
	for _, entry := range h.server.Activity.Snapshot(true).History {
		decisions[entry.Approval] = true
	}
	if !decisions["policy"] || !decisions["once"] {
		t.Fatalf("decisions=%v", decisions)
	}
}

func TestUnpromptedDefaultSkipsApproval(t *testing.T) {
	h, _ := startServer(t, func(context.Context, approval.Summary) error {
		t.Error("unprompted default asked for approval")
		return nil
	}, "", time.Second)
	var err error
	h.server.Policy, err = policy.Parse([]byte(`{"default":"allow","default_approval":"none"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code, err := h.run(context.Background(), []string{"printf", "ran"}, strings.NewReader(""), &out, io.Discard); err != nil || code != 0 || out.String() != "ran" {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
