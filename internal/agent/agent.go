package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/antoniomika/lend/internal/activity"
	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/device"
	"github.com/antoniomika/lend/internal/policy"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

type Server struct {
	Socket          string
	Upstream        string
	Directory       string
	Approve         approval.Approver
	Decide          approval.Decider
	Activity        *activity.Store
	Session         string
	SessionBound    bool
	DeviceCheck     func(context.Context) (device.State, error)
	ApprovalTimeout time.Duration
	CommandTimeout  time.Duration
	Policy          *policy.Policy
	approvals       chan struct{}
	initOnce        sync.Once
	leaseMu         sync.Mutex
	deviceMu        sync.Mutex
	deviceStatus    string
	leases          map[string]grant
	leaseGeneration uint64
	signMu          sync.Mutex
	signUses        map[string]int
	dialUpstream    func(context.Context) (net.Conn, error)
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if (s.Approve == nil && s.Decide == nil) || s.Policy == nil || s.ApprovalTimeout <= 0 || s.CommandTimeout <= 0 {
		return errors.New("policy, approval, and positive timeouts are required")
	}
	s.initActivity()
	s.approvals = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	if s.SessionBound && s.Policy.HasLeases() {
		wg.Add(1)
		go func() { defer wg.Done(); s.WatchDevice(ctx) }()
	}
	slots := make(chan struct{}, 32)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				s.handle(ctx, conn)
			}()
		default:
			conn.Close()
		}
	}
}

func (s *Server) handle(parent context.Context, conn net.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer conn.Close()
	info := connectionInfo{peer: caller.LocalPeer(ctx, conn)}
	s.initActivity()
	connectionCtx, id, err := s.Activity.Begin(ctx, "", s.Session, "connection", approval.Summary{Peer: info.peer})
	if err != nil {
		return
	}
	ctx = connectionCtx
	info.id = id
	defer s.Activity.Finish(info.id, "disconnected", nil)
	stopConnection := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopConnection()
	packets := make(chan []byte)
	go func() {
		for {
			p, err := protocol.Read(conn)
			if err != nil {
				cancel()
				return
			}
			select {
			case packets <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	var upstream net.Conn
	defer func() {
		if upstream != nil {
			upstream.Close()
		}
	}()
	exchange := func(packet []byte) ([]byte, error) {
		var err error
		// Keep one upstream connection so session bindings stay attached to later requests.
		if upstream == nil {
			if s.dialUpstream != nil {
				upstream, err = s.dialUpstream(ctx)
			} else {
				upstream, err = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", s.Upstream)
			}
			if err != nil {
				return nil, err
			}
		}
		conn.SetDeadline(time.Now().Add(2 * time.Minute))
		upstream.SetDeadline(time.Now().Add(2 * time.Minute))
		upstreamConn := upstream
		stop := context.AfterFunc(ctx, func() { upstreamConn.Close() })
		defer stop()
		if err := protocol.Write(upstream, packet); err != nil {
			return nil, err
		}
		return protocol.Read(upstream)
	}
	reject := func() bool { return protocol.Write(conn, []byte{protocol.AgentFailure}) == nil }
	for {
		conn.SetDeadline(time.Now().Add(2 * time.Minute))
		var packet []byte
		select {
		case packet = <-packets:
		case <-ctx.Done():
			return
		}
		if packet[0] == protocol.AgentExtension {
			name, data, err := protocol.ParseExtension(packet)
			if err != nil {
				protocol.Write(conn, []byte{protocol.ExtensionFailure})
				return
			}
			if name == protocol.Extension {
				if upstream != nil {
					upstream.Close()
					upstream = nil
				}
				s.execute(ctx, conn, data, packets, info)
				return
			}
			if name == "query" && len(data) == 0 {
				reply := protocol.ExtensionPacket(protocol.ExtensionResponse, "query", nil)
				for _, extension := range []string{"query", sshagent.SessionBind, protocol.Extension} {
					reply = append(reply, sshagent.String([]byte(extension))...)
				}
				if protocol.Write(conn, reply) != nil {
					return
				}
				continue
			}
			binding, err := sshagent.ParseSessionBind(data)
			if name != sshagent.SessionBind || err != nil {
				if !reject() {
					return
				}
				continue
			}
			reply, err := exchange(packet)
			if err != nil {
				reject()
				return
			}
			if len(reply) != 1 || (reply[0] != 5 && reply[0] != 6 && reply[0] != 28) {
				reject()
				return
			}
			if reply[0] == 6 {
				info.bind(binding)
			}
			if protocol.Write(conn, reply) != nil {
				return
			}
			continue
		}
		if sshagent.IsManagement(packet[0]) {
			reply, err := s.manage(ctx, conn, packet, info, exchange)
			if protocol.Write(conn, reply) != nil || err != nil {
				return
			}
			continue
		}
		switch packet[0] {
		case sshagent.RequestIdentities:
			if len(packet) != 1 {
				if !reject() {
					return
				}
				continue
			}
			if s.Policy == nil || (s.Policy.SSH.Default != "allow" && len(s.Policy.SSH.Keys) == 0) {
				if protocol.Write(conn, sshagent.EncodeIdentities(nil)) != nil {
					return
				}
				continue
			}
			reply, err := exchange(packet)
			if err != nil {
				reject()
				return
			}
			if len(reply) == 1 && reply[0] == protocol.AgentFailure {
				if !reject() {
					return
				}
				continue
			}
			ids, err := sshagent.ParseIdentities(reply)
			if err != nil {
				reject()
				return
			}
			visible := ids[:0]
			for _, id := range ids {
				if _, err := s.Policy.SSHKey(sshagent.Fingerprint(id.Blob)); err == nil {
					visible = append(visible, id)
				}
			}
			if protocol.Write(conn, sshagent.EncodeIdentities(visible)) != nil {
				return
			}
		case sshagent.SignRequest:
			reply, err := s.sign(ctx, conn, packet, info, exchange)
			if protocol.Write(conn, reply) != nil || err != nil {
				return
			}
		default:
			if !reject() {
				return
			}
		}
	}
}

type stream struct {
	conn net.Conn
	mu   sync.Mutex
}

func (w *stream) send(kind byte, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return protocol.Write(w.conn, append([]byte{kind}, data...))
}

type output struct {
	stream *stream
	kind   byte
}

func (w output) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), protocol.ChunkSize)
		if err := w.stream.send(w.kind, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *Server) execute(parent context.Context, conn net.Conn, data []byte, packets <-chan []byte, info connectionInfo) {
	reject := func() { protocol.Write(conn, []byte{protocol.ExtensionFailure}) }
	var request protocol.Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Validate() != nil {
		reject()
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		reject()
		return
	}
	summary := info.summary(approval.Summary{Executable: request.Args[0], Args: request.Args, Directory: s.Directory, Reason: request.Reason, Caller: request.Caller})
	parent, finish, err := s.begin(parent, info, summary)
	if err != nil {
		reject()
		return
	}
	outcome := "denied"
	var exitCode *int
	defer func() { finish(outcome, exitCode) }()
	stopRequest := context.AfterFunc(parent, func() { conn.Close() })
	defer stopRequest()
	path, err := policy.Resolve(request.Args[0], s.Directory)
	if err != nil {
		reject()
		return
	}
	rule, err := s.Policy.Command(path, request)
	if err != nil {
		reject()
		return
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	conn.SetDeadline(time.Now().Add(s.ApprovalTimeout + 5*time.Second))
	// Read immediately to detect a disconnect while the local approval dialog is open.
	input := make(chan []byte)
	var ready atomic.Bool
	go func() {
		for {
			var packet []byte
			select {
			case packet = <-packets:
			case <-ctx.Done():
				return
			}
			if !ready.Load() {
				cancel()
				return
			}
			select {
			case input <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()
	summary.Executable = path
	summary.Requirement = rule.Approval
	summary.Credentials = rule.Secrets
	summary.Lease = leaseOffer(rule.Lease, "exact command arguments and local directory; stdin may vary")
	err = s.approve(ctx, summary)
	if err != nil || ctx.Err() != nil {
		outcome = refusalOutcome(ctx, err)
		reject()
		return
	}

	runCtx, runCancel := context.WithTimeout(ctx, s.CommandTimeout)
	defer runCancel()
	conn.SetDeadline(time.Now().Add(s.CommandTimeout + 5*time.Second))
	w := &stream{conn: conn}
	outcome = "failed"
	s.stage(ctx, "credentials")
	environment, err := s.commandEnvironment(runCtx, rule.Secrets)
	if err != nil {
		reject()
		return
	}
	defer clear(environment)
	cmd := exec.CommandContext(runCtx, path, request.Args[1:]...)
	cmd.Args = append([]string(nil), request.Args...)
	cmd.Dir = s.Directory
	cmd.Env = environment
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		reject()
		return
	}
	defer stdin.Close()
	cmd.Stdout = output{stream: w, kind: protocol.Stdout}
	cmd.Stderr = output{stream: w, kind: protocol.Stderr}
	ready.Store(true)
	if err := protocol.Write(conn, protocol.ExtensionPacket(protocol.ExtensionResponse, protocol.Extension, []byte{protocol.Ready})); err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		w.send(protocol.Error, []byte("could not start approved command"))
		return
	}
	s.stage(ctx, "running")
	// Reap descendants that remain in the command's process group.
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	stop := context.AfterFunc(runCtx, func() { conn.Close(); stdin.Close() })
	defer stop()
	go func() {
		eof := false
		for {
			select {
			case <-runCtx.Done():
				return
			case packet := <-input:
				switch {
				case packet[0] == protocol.Stdin && !eof:
					if _, err := stdin.Write(packet[1:]); err != nil {
						// Keep reading so commands that close stdin can still return their status.
						stdin.Close()
					}
				case packet[0] == protocol.StdinEOF && len(packet) == 1 && !eof:
					eof = true
					stdin.Close()
				default:
					runCancel()
					return
				}
			}
		}
	}()
	err = cmd.Wait()
	status := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			status = exitErr.ExitCode()
			if state, ok := exitErr.Sys().(syscall.WaitStatus); ok && state.Signaled() {
				status = 128 + int(state.Signal())
			}
		} else {
			w.send(protocol.Error, []byte(fmt.Sprintf("command failed: %v", err)))
			status = 125
		}
	}
	var code [4]byte
	binary.BigEndian.PutUint32(code[:], uint32(status))
	w.send(protocol.Exit, code[:])
	exitCode = &status
	outcome = "completed"
	if runCtx.Err() != nil {
		outcome = "cancelled"
	}
}
