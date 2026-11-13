package sshagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

const (
	RequestIdentities byte = 11
	IdentitiesAnswer  byte = 12
	SignRequest       byte = 13
	SignResponse      byte = 14
	SessionBind            = "session-bind@openssh.com"
)

type Identity struct {
	Blob    []byte
	Comment []byte
}

type SigningRequest struct {
	Key         []byte
	Data        []byte
	Flags       uint32
	Fingerprint string
	KeyType     string
	Purpose     string
	Namespace   string
}

func Fingerprint(blob []byte) string {
	hash := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

type reader struct {
	data []byte
	err  error
}

func (r *reader) uint32() uint32 {
	if len(r.data) < 4 {
		r.err = errors.New("truncated SSH uint32")
		return 0
	}
	n := binary.BigEndian.Uint32(r.data[:4])
	r.data = r.data[4:]
	return n
}

func (r *reader) string() []byte {
	n := r.uint32()
	if r.err != nil || uint64(n) > uint64(len(r.data)) {
		r.err = errors.New("truncated SSH string")
		return nil
	}
	p := r.data[:int(n)]
	r.data = r.data[int(n):]
	return p
}

func (r *reader) byte() byte {
	if len(r.data) == 0 {
		r.err = errors.New("truncated SSH byte")
		return 0
	}
	b := r.data[0]
	r.data = r.data[1:]
	return b
}

func (r *reader) done() bool { return r.err == nil && len(r.data) == 0 }

func String(p []byte) []byte {
	b := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(b, uint32(len(p)))
	copy(b[4:], p)
	return b
}

func KeyType(blob []byte) (string, error) {
	r := reader{data: blob}
	kind := r.string()
	if r.err != nil || len(kind) == 0 || len(r.data) == 0 {
		return "", errors.New("invalid SSH public key blob")
	}
	return string(kind), nil
}

func ParseIdentities(p []byte) ([]Identity, error) {
	if len(p) < 5 || p[0] != IdentitiesAnswer {
		return nil, errors.New("invalid identities reply")
	}
	r := reader{data: p[1:]}
	n := r.uint32()
	if uint64(n) > uint64(len(r.data)/8) {
		return nil, errors.New("invalid identity count")
	}
	identities := make([]Identity, 0, int(n))
	for i := uint32(0); i < n; i++ {
		id := Identity{Blob: r.string(), Comment: r.string()}
		if _, err := KeyType(id.Blob); err != nil || r.err != nil {
			return nil, errors.New("invalid agent identity")
		}
		identities = append(identities, id)
	}
	if !r.done() {
		return nil, errors.New("trailing identity data")
	}
	return identities, nil
}

func EncodeIdentities(ids []Identity) []byte {
	p := []byte{IdentitiesAnswer, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(p[1:], uint32(len(ids)))
	for _, id := range ids {
		p = append(p, String(id.Blob)...)
		p = append(p, String(id.Comment)...)
	}
	return p
}

func ParseSign(p []byte) (SigningRequest, error) {
	if len(p) == 0 || p[0] != SignRequest {
		return SigningRequest{}, errors.New("invalid signing request")
	}
	r := reader{data: p[1:]}
	s := SigningRequest{Key: r.string(), Data: r.string(), Flags: r.uint32()}
	if !r.done() || (s.Flags != 0 && s.Flags != 2 && s.Flags != 4) {
		return s, errors.New("invalid signing fields or flags")
	}
	var err error
	s.KeyType, err = KeyType(s.Key)
	if err != nil {
		return s, err
	}
	s.Fingerprint = Fingerprint(s.Key)
	s.Purpose, s.Namespace = purpose(s)
	return s, nil
}

func purpose(s SigningRequest) (string, string) {
	if bytes.HasPrefix(s.Data, []byte("SSHSIG")) {
		r := reader{data: s.Data[6:]}
		namespace := r.string()
		r.string()
		hash := string(r.string())
		digest := r.string()
		if r.done() && len(namespace) > 0 && ((hash == "sha256" && len(digest) == 32) || (hash == "sha512" && len(digest) == 64)) {
			return "sshsig", string(namespace)
		}
	}
	r := reader{data: s.Data}
	session := r.string()
	message := r.byte()
	user := r.string()
	service := string(r.string())
	method := string(r.string())
	signed := r.byte()
	algorithm := string(r.string())
	key := r.string()
	if method == "publickey-hostbound-v00@openssh.com" {
		hostkey := r.string()
		if _, err := KeyType(hostkey); err != nil {
			return "raw", ""
		}
	}
	if r.done() && len(session) > 0 && message == 50 && len(user) > 0 && service == "ssh-connection" && (method == "publickey" || method == "publickey-hostbound-v00@openssh.com") && signed == 1 && bytes.Equal(key, s.Key) && matchesAlgorithm(s.KeyType, algorithm) {
		return "ssh", ""
	}
	return "raw", ""
}

func matchesAlgorithm(key, algorithm string) bool {
	if key == algorithm {
		return true
	}
	if key == "ssh-rsa" {
		return algorithm == "rsa-sha2-256" || algorithm == "rsa-sha2-512"
	}
	if key == "ssh-rsa-cert-v01@openssh.com" {
		return algorithm == "rsa-sha2-256-cert-v01@openssh.com" || algorithm == "rsa-sha2-512-cert-v01@openssh.com"
	}
	return false
}

type Binding struct {
	Fingerprint string
	Forwarding  bool
}

func ParseSessionBind(data []byte) (Binding, error) {
	r := reader{data: data}
	key := r.string()
	session := r.string()
	signature := r.string()
	forwarding := r.byte()
	if _, err := KeyType(key); err != nil || !r.done() || len(session) == 0 || len(signature) == 0 || forwarding > 1 {
		return Binding{}, errors.New("invalid session binding")
	}
	return Binding{Fingerprint: Fingerprint(key), Forwarding: forwarding == 1}, nil
}

func ValidateSessionBind(data []byte) error {
	_, err := ParseSessionBind(data)
	return err
}

func ValidateSignature(p []byte) error {
	if len(p) == 1 && p[0] == 5 {
		return nil
	}
	if len(p) == 0 || p[0] != SignResponse {
		return errors.New("invalid signature reply")
	}
	r := reader{data: p[1:]}
	signature := r.string()
	if !r.done() {
		return errors.New("trailing signature data")
	}
	inner := reader{data: signature}
	algorithm, value := inner.string(), inner.string()
	if string(algorithm) == "sk-ecdsa-sha2-nistp256@openssh.com" || string(algorithm) == "sk-ssh-ed25519@openssh.com" || string(algorithm) == "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" {
		inner.byte()
		inner.uint32()
		if string(algorithm) == "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" {
			inner.string()
			inner.string()
			inner.string()
		}
	}
	if !inner.done() || len(algorithm) == 0 || len(value) == 0 {
		return errors.New("invalid SSH signature")
	}
	return nil
}
