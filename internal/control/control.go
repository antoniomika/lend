package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/antoniomika/lend/internal/activity"
)

type Request struct {
	Action string `json:"action"`
	ID     string `json:"id,omitempty"`
}
type Lease struct {
	ID        string    `json:"id"`
	Scope     string    `json:"scope"`
	Expires   time.Time `json:"expires"`
	Remaining int       `json:"remaining"`
}
type Response struct {
	activity.Snapshot
	PID           int            `json:"pid,omitempty"`
	Session       string         `json:"session,omitempty"`
	LeaseTracking string         `json:"lease_tracking,omitempty"`
	Leases        []Lease        `json:"leases,omitempty"`
	SignatureUses map[string]int `json:"signature_uses,omitempty"`
	Error         string         `json:"error,omitempty"`
}

func Serve(ctx context.Context, listener net.Listener, handle func(Request) Response) error {
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, 8)
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
		default:
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			ServeConn(conn, handle)
		}()
	}
}

func ServeConn(conn net.Conn, handle func(Request) Response) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(conn, 4096))
	decoder.DisallowUnknownFields()
	var request Request
	if decoder.Decode(&request) != nil {
		return
	}
	json.NewEncoder(conn).Encode(handle(request))
}

func Call(ctx context.Context, socket string, request Request) (Response, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	return CallConn(ctx, conn, request)
}

func CallConn(ctx context.Context, conn net.Conn, request Request) (Response, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, err
	}
	var response Response
	err := json.NewDecoder(io.LimitReader(conn, 32*1024*1024)).Decode(&response)
	if err == nil && response.Error != "" {
		err = errors.New(response.Error)
	}
	return response, err
}
