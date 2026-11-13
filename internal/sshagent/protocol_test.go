package sshagent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureKey() []byte {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	return append(String([]byte("ssh-ed25519")), String(private.Public().(ed25519.PublicKey))...)
}

func signingPacket(key, data []byte) []byte {
	p := append([]byte{SignRequest}, String(key)...)
	p = append(p, String(data)...)
	return append(p, 0, 0, 0, 0)
}

func authPayload(key []byte, method string) []byte {
	p := String([]byte("session"))
	p = append(p, 50)
	for _, field := range [][]byte{[]byte("user"), []byte("ssh-connection"), []byte(method)} {
		p = append(p, String(field)...)
	}
	p = append(p, 1)
	p = append(p, String([]byte("ssh-ed25519"))...)
	p = append(p, String(key)...)
	if method == "publickey-hostbound-v00@openssh.com" {
		p = append(p, String(fixtureKey())...)
	}
	return p
}

func sshsigPayload(namespace string) []byte {
	p := []byte("SSHSIG")
	for _, field := range [][]byte{[]byte(namespace), nil, []byte("sha256"), make([]byte, 32)} {
		p = append(p, String(field)...)
	}
	return p
}

func TestSigningPurposeClassification(t *testing.T) {
	key := fixtureKey()
	for _, tc := range []struct {
		name               string
		payload            []byte
		purpose, namespace string
	}{
		{"SSH authentication", authPayload(key, "publickey"), "ssh", ""},
		{"hostbound authentication", authPayload(key, "publickey-hostbound-v00@openssh.com"), "ssh", ""},
		{"SSHSIG git", sshsigPayload("git"), "sshsig", "git"},
		{"SSHSIG file", sshsigPayload("file"), "sshsig", "file"},
		{"raw", []byte("arbitrary data"), "raw", ""},
		{"truncated SSHSIG", []byte("SSHSIG"), "raw", ""},
		{"trailing SSHSIG data", append(sshsigPayload("git"), 1), "raw", ""},
		{"empty namespace", sshsigPayload(""), "raw", ""},
		{"trailing auth data", append(authPayload(key, "publickey"), 1), "raw", ""},
		{"different auth key", authPayload(append(bytes.Clone(key), 1), "publickey"), "raw", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseSign(signingPacket(key, tc.payload))
			if err != nil || r.Purpose != tc.purpose || r.Namespace != tc.namespace {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func TestRejectMalformedSigningRequests(t *testing.T) {
	valid := signingPacket(fixtureKey(), []byte("data"))
	badFlags := bytes.Clone(valid)
	badFlags[len(badFlags)-1] = 8
	for _, p := range [][]byte{nil, {13}, {13, 255, 255, 255, 255}, valid[:len(valid)-1], append(bytes.Clone(valid), 1), badFlags, signingPacket(nil, nil)} {
		if _, err := ParseSign(p); err == nil {
			t.Fatalf("malformed signing request accepted: %v", p)
		}
	}
}

func TestFingerprintMatchesOpenSSHForPlainKey(t *testing.T) {
	tool, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	path := filepath.Join(t.TempDir(), "key.pub")
	key := fixtureKey()
	if err := os.WriteFile(path, []byte("ssh-ed25519 "+base64.StdEncoding.EncodeToString(key)+" fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(tool, "-E", "sha256", "-lf", path).CombinedOutput()
	if err != nil || !strings.Contains(string(output), Fingerprint(key)) {
		t.Fatalf("OpenSSH fingerprint mismatch: %s %v", output, err)
	}
}

func TestIdentitiesRejectMalformedLengths(t *testing.T) {
	valid := EncodeIdentities([]Identity{{Blob: fixtureKey(), Comment: []byte("fixture")}})
	ids, err := ParseIdentities(valid)
	if err != nil || len(ids) != 1 || !bytes.Equal(ids[0].Blob, fixtureKey()) {
		t.Fatalf("%v %v", ids, err)
	}
	for _, p := range [][]byte{nil, {12, 255, 255, 255, 255}, valid[:len(valid)-1], append(bytes.Clone(valid), 1)} {
		if _, err := ParseIdentities(p); err == nil {
			t.Fatalf("malformed identities accepted: %v", p)
		}
	}
}

func TestSecurityKeySignatureFormats(t *testing.T) {
	for _, kind := range []string{"ssh-ed25519", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"} {
		inner := append(String([]byte(kind)), String([]byte("signature"))...)
		if strings.Contains(kind, "sk-") {
			inner = append(inner, 1, 0, 0, 0, 1)
		}
		if strings.HasPrefix(kind, "webauthn-") {
			for _, field := range []string{"origin", "clientData", ""} {
				inner = append(inner, String([]byte(field))...)
			}
		}
		packet := append([]byte{14}, String(inner)...)
		if err := ValidateSignature(packet); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if err := ValidateSignature(append(packet, 1)); err == nil {
			t.Fatalf("%s accepted trailing data", kind)
		}
	}
}

func FuzzAgentPackets(f *testing.F) {
	f.Add(signingPacket(fixtureKey(), authPayload(fixtureKey(), "publickey")))
	f.Add(signingPacket(fixtureKey(), sshsigPayload("git")))
	f.Add(EncodeIdentities([]Identity{{Blob: fixtureKey()}}))
	f.Add([]byte{13, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, p []byte) {
		ParseSign(p)
		ParseIdentities(p)
		ValidateSignature(p)
		ValidateSessionBind(p)
	})
}
