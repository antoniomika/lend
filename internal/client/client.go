package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/protocol"
)

func Run(ctx context.Context, socket string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return RunRequest(ctx, socket, protocol.Request{Args: args}, stdin, stdout, stderr)
}

func RunRequest(ctx context.Context, socket string, request protocol.Request, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if request.Caller == nil {
		who := caller.Capture(ctx, "client")
		request.Caller = &who
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return 125, err
	}
	return RunRequestConn(ctx, conn, request, stdin, stdout, stderr)
}

func RunConn(ctx context.Context, conn net.Conn, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return RunRequestConn(ctx, conn, protocol.Request{Args: args}, stdin, stdout, stderr)
}

func RunRequestConn(ctx context.Context, conn net.Conn, request protocol.Request, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	defer conn.Close()
	packet, err := protocol.EncodeRequest(request)
	if err != nil {
		return 125, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := protocol.Write(conn, packet); err != nil {
		return 125, err
	}
	reply, err := protocol.Read(conn)
	if err != nil {
		return 125, err
	}
	if reply[0] == protocol.AgentFailure {
		return 125, errors.New("agent does not support lend; forward the lend agent socket")
	}
	if reply[0] == protocol.ExtensionFailure {
		return 125, errors.New("request refused: policy, approval, unavailable command, or credential retrieval")
	}
	name, body, err := protocol.ParseExtension(reply)
	if err != nil || reply[0] != protocol.ExtensionResponse || name != protocol.Extension || len(body) != 1 || body[0] != protocol.Ready {
		return 125, errors.New("invalid lend handshake")
	}
	go func() {
		buf := make([]byte, protocol.ChunkSize)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				if protocol.Write(conn, append([]byte{protocol.Stdin}, buf[:n]...)) != nil {
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					protocol.Write(conn, []byte{protocol.StdinEOF})
				} else {
					conn.Close()
				}
				return
			}
		}
	}()
	for {
		p, err := protocol.Read(conn)
		if err != nil {
			return 125, fmt.Errorf("command channel closed: %w", err)
		}
		switch p[0] {
		case protocol.Stdout:
			if _, err := stdout.Write(p[1:]); err != nil {
				return 125, err
			}
		case protocol.Stderr:
			if _, err := stderr.Write(p[1:]); err != nil {
				return 125, err
			}
		case protocol.Error:
			return 125, errors.New(string(p[1:]))
		case protocol.Exit:
			if len(p) != 5 {
				return 125, errors.New("invalid exit status")
			}
			code := binary.BigEndian.Uint32(p[1:])
			if code > 255 {
				return 125, errors.New("invalid exit status")
			}
			return int(code), nil
		default:
			return 125, errors.New("unexpected command packet")
		}
	}
}
