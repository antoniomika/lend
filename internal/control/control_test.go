package control

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLocalControlRoundTripAndValidation(t *testing.T) {
	for _, action := range []string{"status", "pause"} {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			ServeConn(server, func(request Request) Response {
				if request.Action != action {
					t.Error("action changed")
				}
				return Response{Session: "development"}
			})
		}()
		response, err := CallConn(context.Background(), client, Request{Action: action})
		client.Close()
		<-done
		if err != nil || response.Session != "development" {
			t.Fatalf("%+v %v", response, err)
		}
	}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		ServeConn(server, func(Request) Response { t.Error("invalid control request reached handler"); return Response{} })
	}()
	client.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(client, `{"action":"status","unknown":true}`+"\n")
	var data [1]byte
	if _, err := client.Read(data[:]); err == nil {
		t.Fatal("unknown field accepted")
	}
	client.Close()
	<-done
}

func TestControlCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CallConn(ctx, client, Request{Action: strings.Repeat("x", 10)}); err == nil {
		t.Fatal("cancelled control call succeeded")
	}
}
