package sshagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"math/big"
	"strings"
	"unicode/utf8"
)

type ManagementRequest struct {
	Operation   string
	Fingerprint string
	KeyType     string
	Provider    string
	Lifetime    *uint32
	Confirm     bool
	Extensions  []string
}

func IsManagement(kind byte) bool {
	return kind == 17 || kind == 18 || kind == 19 || kind == 20 || kind == 21 || kind == 22 || kind == 23 || kind == 25 || kind == 26
}

func ManagementOperation(operation string) bool {
	switch operation {
	case "add-key", "remove-key", "remove-all-keys", "lock", "unlock", "add-provider", "remove-provider":
		return true
	}
	return false
}

func ParseManagement(p []byte) (ManagementRequest, error) {
	var m ManagementRequest
	if len(p) == 0 || !IsManagement(p[0]) {
		return m, errors.New("unsupported agent management operation")
	}
	r := reader{data: p[1:]}
	switch p[0] {
	case 17, 25:
		m.Operation = "add-key"
		public, kind, err := privatePublic(&r)
		if err != nil {
			return ManagementRequest{}, errors.New("invalid or unsupported private key")
		}
		m.KeyType, m.Fingerprint = kind, Fingerprint(public)
		r.cstring(4096)
	case 18:
		m.Operation = "remove-key"
		public := r.string()
		var err error
		m.KeyType, _, err = decodePublic(public)
		if err != nil {
			return ManagementRequest{}, errors.New("invalid public key")
		}
		m.Fingerprint = Fingerprint(public)
	case 19:
		m.Operation = "remove-all-keys"
	case 20, 21, 26:
		m.Operation = "add-provider"
		if p[0] == 21 {
			m.Operation = "remove-provider"
		}
		m.Provider = r.cstring(4096)
		if m.Provider == "" {
			r.err = errors.New("empty provider identifier")
		}
		r.cstringBytes()
	case 22, 23:
		m.Operation = "lock"
		if p[0] == 23 {
			m.Operation = "unlock"
		}
		if len(r.cstringBytes()) == 0 {
			r.err = errors.New("empty lock passphrase")
		}
	}
	if (p[0] == 25 || p[0] == 26) && r.err == nil {
		if err := parseConstraints(&r, &m); err != nil {
			return ManagementRequest{}, err
		}
	}
	if !r.done() {
		return ManagementRequest{}, errors.New("malformed agent management request")
	}
	return m, nil
}

func (r *reader) cstringBytes() []byte {
	p := r.string()
	if bytes.IndexByte(p, 0) >= 0 {
		r.err = errors.New("NUL in SSH cstring")
	}
	return p
}

func (r *reader) cstring(max int) string {
	p := r.cstringBytes()
	if len(p) > max || !utf8.Valid(p) {
		r.err = errors.New("invalid SSH text field")
	}
	return string(p)
}

func parseConstraints(r *reader, m *ManagementRequest) error {
	seen := make(map[string]bool)
	for len(r.data) > 0 && r.err == nil {
		var name string
		switch r.byte() {
		case 1:
			name = "lifetime"
			seconds := r.uint32()
			m.Lifetime = &seconds
		case 2:
			name = "confirm"
			m.Confirm = true
		case 255:
			name = r.cstring(128)
			switch name {
			case "sk-provider@openssh.com":
				if m.Operation != "add-key" || !strings.HasPrefix(m.KeyType, "sk-") {
					return errors.New("provider constraint requires a security key")
				}
				m.Provider = r.cstring(4096)
				if m.Provider == "" {
					return errors.New("empty security key provider")
				}
			case "restrict-destination-v00@openssh.com":
				if len(r.string()) == 0 {
					return errors.New("empty destination constraints")
				}
			case "associated-certs-v00@openssh.com":
				if m.Operation != "add-provider" || r.byte() > 1 {
					return errors.New("invalid associated certificate constraint")
				}
				certs := reader{data: r.string()}
				count := 0
				for len(certs.data) > 0 && certs.err == nil {
					kind, err := KeyType(certs.string())
					if err != nil || !strings.Contains(kind, "-cert-v01@") {
						return errors.New("invalid associated certificate")
					}
					count++
					if count > 16 {
						return errors.New("too many associated certificates")
					}
				}
				if !certs.done() {
					return errors.New("malformed associated certificates")
				}
			default:
				return errors.New("unsupported agent constraint extension")
			}
			m.Extensions = append(m.Extensions, name)
		default:
			return errors.New("unsupported agent constraint")
		}
		if seen[name] {
			return errors.New("duplicate agent constraint")
		}
		seen[name] = true
	}
	return r.err
}

func (r *reader) mpint() *big.Int {
	p := r.string()
	if len(p) == 0 || len(p) > 2049 || p[0]&128 != 0 || (len(p) > 1 && p[0] == 0 && p[1]&128 == 0) {
		r.err = errors.New("invalid positive mpint")
		return new(big.Int)
	}
	n := new(big.Int).SetBytes(p)
	if n.BitLen() > 16384 {
		r.err = errors.New("mpint exceeds supported size")
	}
	return n
}

func mpintBytes(n *big.Int) []byte {
	p := n.Bytes()
	if len(p) > 0 && p[0]&128 != 0 {
		p = append([]byte{0}, p...)
	}
	return String(p)
}

type publicParts struct {
	numbers     []*big.Int
	public      []byte
	curve       string
	application string
}

func baseKeyType(kind string) string {
	if kind == "sk-ssh-ed25519-cert-v01@openssh.com" {
		return "sk-ssh-ed25519@openssh.com"
	}
	if kind == "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" {
		return "sk-ecdsa-sha2-nistp256@openssh.com"
	}
	return strings.Replace(kind, "-cert-v01@openssh.com", "", 1)
}

func publicFields(r *reader, kind string) publicParts {
	var parts publicParts
	switch kind {
	case "ssh-rsa":
		parts.numbers = []*big.Int{r.mpint(), r.mpint()}
	case "ssh-dss":
		for i := 0; i < 4; i++ {
			parts.numbers = append(parts.numbers, r.mpint())
		}
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		parts.public = r.string()
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com":
		parts.curve, parts.public = r.cstring(16), r.string()
	default:
		r.err = errors.New("unsupported key type")
	}
	if strings.HasPrefix(kind, "sk-") {
		parts.application = r.cstring(4096)
	}
	return parts
}

func decodePublic(blob []byte) (string, publicParts, error) {
	r := reader{data: blob}
	kind := r.cstring(128)
	base := baseKeyType(kind)
	if base != kind {
		r.string()
	}
	parts := publicFields(&r, base)
	if base != kind {
		r.uint32()
		r.uint32()
		r.uint32()
		r.string()
		r.string()
		r.uint32()
		r.uint32()
		r.uint32()
		r.uint32()
		for i := 0; i < 5; i++ {
			r.string()
		}
	}
	if !r.done() {
		return kind, parts, errors.New("invalid public key encoding")
	}
	switch base {
	case "ssh-rsa":
		if parts.numbers[0].Sign() <= 0 || parts.numbers[1].Sign() <= 0 {
			return kind, parts, errors.New("invalid RSA public key")
		}
	case "ssh-dss":
		for _, n := range parts.numbers {
			if n.Sign() <= 0 {
				return kind, parts, errors.New("invalid DSA public key")
			}
		}
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		if len(parts.public) != 32 {
			return kind, parts, errors.New("invalid Ed25519 public key")
		}
	default:
		curve := curveFor(parts.curve)
		if curve == nil || !validPoint(curve, parts.public) {
			return kind, parts, errors.New("invalid curve public key")
		}
	}
	return kind, parts, nil
}

func privatePublic(r *reader) ([]byte, string, error) {
	kind := r.cstring(128)
	base := baseKeyType(kind)
	var cert []byte
	var parts publicParts
	if base != kind {
		cert = r.string()
		certKind, certParts, err := decodePublic(cert)
		if err != nil || certKind != kind {
			return nil, kind, errors.New("certificate type mismatch")
		}
		parts = certParts
	}
	public := String([]byte(base))
	if base == "ssh-rsa" {
		var e, n *big.Int
		if cert == nil {
			n, e = r.mpint(), r.mpint()
		} else {
			e, n = parts.numbers[0], parts.numbers[1]
		}
		d, iqmp, p, q := r.mpint(), r.mpint(), r.mpint(), r.mpint()
		if r.err != nil || !e.IsInt64() || e.Int64() > 1<<31-1 || n.BitLen() > 16384 {
			return nil, kind, errors.New("invalid RSA key")
		}
		one := big.NewInt(1)
		if e.Int64() < 3 || p.Cmp(one) <= 0 || q.Cmp(one) <= 0 || new(big.Int).Mul(p, q).Cmp(n) != 0 {
			return nil, kind, errors.New("invalid RSA private material")
		}
		inverse := new(big.Int).ModInverse(q, p)
		ed := new(big.Int).Mul(e, d)
		if inverse == nil || iqmp.Cmp(inverse) != 0 || new(big.Int).Mod(ed, new(big.Int).Sub(p, one)).Cmp(one) != 0 || new(big.Int).Mod(ed, new(big.Int).Sub(q, one)).Cmp(one) != 0 {
			return nil, kind, errors.New("invalid RSA private material")
		}
		public = append(public, mpintBytes(e)...)
		public = append(public, mpintBytes(n)...)
	} else if base == "ssh-ed25519" {
		pub, private := r.string(), r.string()
		if r.err != nil || len(pub) != 32 || len(private) != 64 {
			return nil, kind, errors.New("invalid Ed25519 key")
		}
		derived := ed25519.NewKeyFromSeed(private[:32])
		defer clear(derived)
		if !bytes.Equal(private, derived) || !bytes.Equal(pub, derived[32:]) || (cert != nil && !bytes.Equal(pub, parts.public)) {
			return nil, kind, errors.New("Ed25519 public/private mismatch")
		}
		public = append(public, String(pub)...)
	} else if base == "ssh-dss" {
		if cert == nil {
			parts = publicFields(r, base)
		}
		x := r.mpint()
		p, q, g, y := parts.numbers[0], parts.numbers[1], parts.numbers[2], parts.numbers[3]
		if r.err != nil || p.Sign() <= 0 || p.BitLen() > 3072 || q.BitLen() > 256 || x.Cmp(q) >= 0 || new(big.Int).Exp(g, x, p).Cmp(y) != 0 {
			return nil, kind, errors.New("invalid DSA key")
		}
		for _, n := range parts.numbers {
			public = append(public, mpintBytes(n)...)
		}
	} else if strings.HasPrefix(base, "sk-") {
		if cert == nil {
			parts = publicFields(r, base)
		} else {
			if base == "sk-ssh-ed25519@openssh.com" && !bytes.Equal(r.string(), parts.public) {
				return nil, kind, errors.New("security key public mismatch")
			}
			if r.cstring(4096) != parts.application {
				return nil, kind, errors.New("security key application mismatch")
			}
		}
		r.byte()
		handle := r.string()
		r.string()
		if len(handle) == 0 {
			return nil, kind, errors.New("missing security key handle")
		}
		if base == "sk-ssh-ed25519@openssh.com" {
			if len(parts.public) != 32 {
				return nil, kind, errors.New("invalid security key public part")
			}
		} else if parts.curve != "nistp256" || !validPoint(elliptic.P256(), parts.public) {
			return nil, kind, errors.New("invalid security key curve")
		}
		if parts.curve != "" {
			public = append(public, String([]byte(parts.curve))...)
		}
		public = append(public, String(parts.public)...)
		public = append(public, String([]byte(parts.application))...)
	} else {
		if cert == nil {
			parts = publicFields(r, base)
		}
		d := r.mpint()
		curve := curveFor(parts.curve)
		if r.err != nil || curve == nil || base != "ecdsa-sha2-"+parts.curve || d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
			return nil, kind, errors.New("invalid ECDSA key")
		}
		x, y := curve.ScalarBaseMult(d.Bytes())
		if !bytes.Equal(elliptic.Marshal(curve, x, y), parts.public) {
			return nil, kind, errors.New("ECDSA public/private mismatch")
		}
		public = append(public, String([]byte(parts.curve))...)
		public = append(public, String(parts.public)...)
	}
	if r.err != nil {
		return nil, kind, r.err
	}
	if cert != nil {
		public = cert
	}
	return public, kind, nil
}

func curveFor(name string) elliptic.Curve {
	switch name {
	case "nistp256":
		return elliptic.P256()
	case "nistp384":
		return elliptic.P384()
	case "nistp521":
		return elliptic.P521()
	}
	return nil
}

func validPoint(curve elliptic.Curve, encoded []byte) bool {
	x, _ := elliptic.Unmarshal(curve, encoded)
	return x != nil
}
