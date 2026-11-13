package doctor

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/antoniomika/lend/internal/protocol"
)

func probe(ctx context.Context, socket string, timeout time.Duration) (bool, error) {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socket)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return probeConn(ctx, conn, timeout)
}

func probeConn(ctx context.Context, conn net.Conn, timeout time.Duration) (bool, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := protocol.Write(conn, protocol.ExtensionPacket(protocol.AgentExtension, "query", nil)); err != nil {
		return false, err
	}
	packet, err := protocol.Read(conn)
	if err != nil {
		return false, err
	}
	if len(packet) == 1 && (packet[0] == protocol.AgentFailure || packet[0] == protocol.ExtensionFailure) {
		return false, nil
	}
	name, data, err := protocol.ParseExtension(packet)
	if err != nil || packet[0] != protocol.ExtensionResponse || name != "query" {
		return false, errors.New("invalid agent extension query response")
	}
	extensions := []string{}
	for len(data) > 0 {
		if len(data) < 4 {
			return false, errors.New("truncated agent extension list")
		}
		n := uint64(binary.BigEndian.Uint32(data[:4]))
		data = data[4:]
		if n == 0 || n > uint64(len(data)) {
			return false, errors.New("invalid agent extension name")
		}
		extensions = append(extensions, string(data[:int(n)]))
		data = data[int(n):]
		if len(extensions) > 256 {
			return false, errors.New("too many agent extensions")
		}
	}
	return slices.Contains(extensions, protocol.Extension), nil
}
