package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	Extension              = "exec-v1@lend.antoniomika.com"
	MaxFrame               = 256 * 1024
	ChunkSize              = 32 * 1024
	AgentFailure      byte = 5
	AgentExtension    byte = 27
	ExtensionFailure  byte = 28
	ExtensionResponse byte = 29
	Ready             byte = 240
	Stdin             byte = 241
	StdinEOF          byte = 242
	Stdout            byte = 243
	Stderr            byte = 244
	Exit              byte = 245
	Error             byte = 246
)

type Request struct {
	Args   []string `json:"args"`
	Reason string   `json:"reason,omitempty"`
	Caller *Caller  `json:"caller,omitempty"`
}

func (r Request) Validate() error {
	if r.Caller != nil {
		if err := r.Caller.Validate(); err != nil {
			return err
		}
	}
	if len(r.Reason) > 2048 || !utf8.ValidString(r.Reason) || strings.ContainsRune(r.Reason, 0) {
		return errors.New("reason must be valid UTF-8 without NUL and at most 2048 bytes")
	}
	if len(r.Args) == 0 || len(r.Args) > 256 || r.Args[0] == "" {
		return errors.New("expected an executable and at most 255 arguments")
	}
	total := 0
	for _, arg := range r.Args {
		if !utf8.ValidString(arg) {
			return errors.New("arguments must contain valid UTF-8")
		}
		if strings.ContainsRune(arg, 0) {
			return errors.New("arguments cannot contain NUL")
		}
		total += len(arg)
	}
	if total > 8192 {
		return errors.New("command exceeds 8192 bytes")
	}
	return nil
}

func Read(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}

func Write(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > MaxFrame {
		return errors.New("invalid frame length")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(p)))
	for _, part := range [][]byte{header[:], p} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}

func ExtensionPacket(kind byte, name string, payload []byte) []byte {
	p := make([]byte, 5+len(name)+len(payload))
	p[0] = kind
	binary.BigEndian.PutUint32(p[1:5], uint32(len(name)))
	copy(p[5:], name)
	copy(p[5+len(name):], payload)
	return p
}

func ParseExtension(p []byte) (string, []byte, error) {
	if len(p) < 5 {
		return "", nil, errors.New("invalid extension packet")
	}
	n := binary.BigEndian.Uint32(p[1:5])
	if uint64(n) > uint64(len(p)-5) {
		return "", nil, errors.New("invalid extension name length")
	}
	return string(p[5 : 5+int(n)]), p[5+int(n):], nil
}

func EncodeRequest(r Request) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	p, err := json.Marshal(r)
	return ExtensionPacket(AgentExtension, Extension, p), err
}
