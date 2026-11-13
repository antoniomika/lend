package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRejectFrameLengths(t *testing.T) {
	for _, size := range []uint32{0, MaxFrame + 1, ^uint32(0)} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], size)
		if _, err := Read(bytes.NewReader(b[:])); err == nil {
			t.Fatalf("accepted length %d", size)
		}
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 11})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Read(bytes.NewReader(data))
		if err == nil {
			if len(p) == 0 || len(p) > MaxFrame {
				t.Fatal("unbounded frame")
			}
			var b bytes.Buffer
			if err := Write(&b, p); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzParseExtension(f *testing.F) {
	f.Add(ExtensionPacket(AgentExtension, Extension, []byte("{}")))
	f.Add([]byte{27, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) { ParseExtension(data) })
}
