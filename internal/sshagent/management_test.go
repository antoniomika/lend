package sshagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func fieldsPacket(kind byte, fields ...[]byte) []byte {
	p := []byte{kind}
	for _, field := range fields {
		p = append(p, String(field)...)
	}
	return p
}

func edAdd() []byte {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	return fieldsPacket(17, []byte("ssh-ed25519"), private[32:], private, []byte("fixture"))
}

func TestManagementOperations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		packet    []byte
		operation string
	}{
		{"add", edAdd(), "add-key"},
		{"remove", fieldsPacket(18, fixtureKey()), "remove-key"},
		{"remove all", []byte{19}, "remove-all-keys"},
		{"lock", fieldsPacket(22, []byte("fixture-passphrase")), "lock"},
		{"unlock", fieldsPacket(23, []byte("fixture-passphrase")), "unlock"},
		{"load provider", fieldsPacket(20, []byte("/example/provider.so"), []byte("fixture-pin")), "add-provider"},
		{"unload provider", fieldsPacket(21, []byte("/example/provider.so"), nil), "remove-provider"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseManagement(tc.packet)
			if err != nil || m.Operation != tc.operation {
				t.Fatalf("operation %q: %v", m.Operation, err)
			}
			if (tc.operation == "add-key" || tc.operation == "remove-key") && m.Fingerprint != Fingerprint(fixtureKey()) {
				t.Fatal("incorrect target key")
			}
		})
	}
}

func TestPrivateKeyPublicIdentity(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey.Precompute()
	rsaPublic := append(String([]byte("ssh-rsa")), mpintBytes(big.NewInt(int64(rsaKey.E)))...)
	rsaPublic = append(rsaPublic, mpintBytes(rsaKey.N)...)
	rsaPacket := []byte{17}
	rsaPacket = append(rsaPacket, String([]byte("ssh-rsa"))...)
	for _, n := range []*big.Int{rsaKey.N, big.NewInt(int64(rsaKey.E)), rsaKey.D, rsaKey.Precomputed.Qinv, rsaKey.Primes[0], rsaKey.Primes[1]} {
		rsaPacket = append(rsaPacket, mpintBytes(n)...)
	}
	rsaPacket = append(rsaPacket, String([]byte("fixture"))...)
	if m, err := ParseManagement(rsaPacket); err != nil || m.Fingerprint != Fingerprint(rsaPublic) {
		t.Fatalf("RSA target: %v", err)
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		name := map[int]string{256: "nistp256", 384: "nistp384", 521: "nistp521"}[curve.Params().BitSize]
		public := elliptic.Marshal(curve, key.X, key.Y)
		blob := append(String([]byte("ecdsa-sha2-"+name)), String([]byte(name))...)
		blob = append(blob, String(public)...)
		p := append([]byte{17}, blob...)
		p = append(p, mpintBytes(key.D)...)
		p = append(p, String([]byte("fixture"))...)
		if m, err := ParseManagement(p); err != nil || m.Fingerprint != Fingerprint(blob) {
			t.Fatalf("ECDSA %s target: %v", name, err)
		}
	}
}

func certificate(kind string, publicFields []byte) []byte {
	p := append(String([]byte(kind)), String([]byte("nonce"))...)
	p = append(p, publicFields...)
	p = append(p, make([]byte, 8)...)
	p = append(p, 0, 0, 0, 1)
	p = append(p, String([]byte("fixture certificate"))...)
	p = append(p, String(nil)...)
	p = append(p, make([]byte, 8)...)
	p = append(p, bytes.Repeat([]byte{255}, 8)...)
	for _, field := range [][]byte{nil, nil, nil, fixtureKey(), []byte("certificate signature")} {
		p = append(p, String(field)...)
	}
	return p
}

func TestCertificateAndSecurityKeyManagement(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	cert := certificate("ssh-ed25519-cert-v01@openssh.com", String(private[32:]))
	p := fieldsPacket(17, []byte("ssh-ed25519-cert-v01@openssh.com"), cert, private[32:], private, []byte("fixture"))
	if m, err := ParseManagement(p); err != nil || m.Fingerprint != Fingerprint(cert) {
		t.Fatalf("certificate target: %v", err)
	}
	if m, err := ParseManagement(fieldsPacket(18, cert)); err != nil || m.Fingerprint != Fingerprint(cert) {
		t.Fatalf("certificate removal: %v", err)
	}
	for _, certified := range []bool{false, true} {
		kind := "sk-ssh-ed25519@openssh.com"
		public := append(String(private[32:]), String([]byte("ssh:"))...)
		blob := append(String([]byte(kind)), public...)
		if certified {
			kind = "sk-ssh-ed25519-cert-v01@openssh.com"
			blob = certificate(kind, public)
		}
		p := fieldsPacket(17, []byte(kind))
		if certified {
			p = append(p, String(blob)...)
		}
		p = append(p, public...)
		p = append(p, 1)
		p = append(p, String([]byte("fixture-handle"))...)
		p = append(p, String(nil)...)
		p = append(p, String([]byte("fixture"))...)
		if m, err := ParseManagement(p); err != nil || m.Fingerprint != Fingerprint(blob) {
			t.Fatalf("security key target: %v", err)
		}
	}
}

func TestManagementConstraints(t *testing.T) {
	p := edAdd()
	p[0] = 25
	p = append(p, 1, 0, 0, 0, 60, 2)
	p = append(p, 255)
	p = append(p, String([]byte("restrict-destination-v00@openssh.com"))...)
	p = append(p, String([]byte("upstream destination data"))...)
	m, err := ParseManagement(p)
	if err != nil || m.Lifetime == nil || *m.Lifetime != 60 || !m.Confirm || len(m.Extensions) != 1 {
		t.Fatalf("constraints: %v", err)
	}
	provider := fieldsPacket(26, []byte("/example/provider.so"), []byte("fixture-pin"))
	provider = append(provider, 2)
	if m, err := ParseManagement(provider); err != nil || !m.Confirm {
		t.Fatalf("provider constraints: %v", err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	sk := fieldsPacket(25, []byte("sk-ssh-ed25519@openssh.com"), key[32:], []byte("ssh:"))
	sk = append(sk, 1)
	sk = append(sk, String([]byte("fixture-handle"))...)
	sk = append(sk, String(nil)...)
	sk = append(sk, String([]byte("fixture"))...)
	sk = append(sk, 255)
	sk = append(sk, String([]byte("sk-provider@openssh.com"))...)
	sk = append(sk, String([]byte("internal"))...)
	if m, err := ParseManagement(sk); err != nil || m.Provider != "internal" {
		t.Fatalf("security key provider: %v", err)
	}
}

func TestECDSASecurityKeyAndCertificate(t *testing.T) {
	curve := elliptic.P256()
	point := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)
	public := append(String([]byte("nistp256")), String(point)...)
	public = append(public, String([]byte("ssh:"))...)
	for _, certified := range []bool{false, true} {
		kind := "sk-ecdsa-sha2-nistp256@openssh.com"
		blob := append(String([]byte(kind)), public...)
		p := fieldsPacket(17, []byte(kind))
		if certified {
			kind = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
			blob = certificate(kind, public)
			p = fieldsPacket(17, []byte(kind), blob, []byte("ssh:"))
		} else {
			p = append(p, public...)
		}
		p = append(p, 1)
		p = append(p, String([]byte("fixture-handle"))...)
		p = append(p, String(nil)...)
		p = append(p, String([]byte("fixture"))...)
		if m, err := ParseManagement(p); err != nil || m.Fingerprint != Fingerprint(blob) {
			t.Fatalf("ECDSA security key: %v", err)
		}
	}
}

func TestRejectMalformedManagement(t *testing.T) {
	add := edAdd()
	for _, p := range [][]byte{
		nil, {17}, {18}, {19, 1}, fieldsPacket(22, nil), fieldsPacket(23, []byte("bad\x00passphrase")),
		fieldsPacket(20, nil, nil), fieldsPacket(21, []byte("provider")), add[:len(add)-1], append(bytes.Clone(add), 2),
		fieldsPacket(17, []byte("unsupported-key"), nil),
		fieldsPacket(17, []byte("ssh-ed25519"), make([]byte, 32), make([]byte, 64), nil),
	} {
		if _, err := ParseManagement(p); err == nil {
			t.Fatal("malformed management request accepted")
		}
	}
	p := edAdd()
	p[0] = 25
	for _, constraints := range [][]byte{{1}, {2, 2}, {99}, {255, 0, 0, 0, 4, 't', 'e', 's', 't'}} {
		if _, err := ParseManagement(append(bytes.Clone(p), constraints...)); err == nil {
			t.Fatal("malformed constraint accepted")
		}
	}
}

func FuzzManagementRequests(f *testing.F) {
	f.Add(edAdd())
	f.Add(fieldsPacket(18, fixtureKey()))
	f.Add(fieldsPacket(22, []byte("fixture-passphrase")))
	f.Add(fieldsPacket(20, []byte("/example/provider.so"), []byte("fixture-pin")))
	for _, kind := range []string{"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "sk-ssh-ed25519@openssh.com"} {
		f.Add(fieldsPacket(17, []byte(kind)))
	}
	rsaSeed := fieldsPacket(17, []byte("ssh-rsa"))
	for _, value := range []int64{253, 3, 147, 21, 23, 11} {
		rsaSeed = append(rsaSeed, mpintBytes(big.NewInt(value))...)
	}
	rsaSeed = append(rsaSeed, String(nil)...)
	f.Add(rsaSeed)
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 256*1024 {
			return
		}
		m, err := ParseManagement(p)
		if err == nil && !ManagementOperation(m.Operation) {
			t.Fatal("unknown management operation parsed")
		}
	})
}
