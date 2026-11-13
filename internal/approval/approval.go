package approval

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/protocol"
	"github.com/antoniomika/lend/internal/sshagent"
)

type Summary struct {
	RequestID        string
	Session          string
	Lease            *LeaseOffer
	Credentials      map[string]string
	Kind             string
	Executable       string
	Args             []string
	Directory        string
	Reason           string
	Requirement      string
	Topic            string
	Title            string
	Details          string
	KeyFingerprint   string
	KeyType          string
	KeyLabel         string
	SigningPurpose   string
	SigningNamespace string
	SigningDigest    string
	SigningBytes     int
	SigningFlags     uint32
	Caller           *protocol.Caller
	Peer             *caller.Peer
	Bindings         []SSHBinding
	OmittedBindings  int
	Management       *sshagent.ManagementRequest
}

type SSHBinding struct {
	Fingerprint string
	Forwarding  bool
}

func (s Summary) String() string {
	var b strings.Builder
	if s.Kind == "ssh-manage" && s.Management != nil {
		m := s.Management
		b.WriteString("A forwarded request wants to change your upstream SSH agent.\nOrigin: unverified\n\n")
		s.writeCaller(&b)
		fmt.Fprintf(&b, "Operation: %s\n", strconv.QuoteToASCII(m.Operation))
		if m.Fingerprint != "" {
			fmt.Fprintf(&b, "Key fingerprint: %s\nKey type: %s\n", strconv.QuoteToASCII(m.Fingerprint), strconv.QuoteToASCII(m.KeyType))
		}
		if m.Provider != "" {
			fmt.Fprintf(&b, "Provider/token identifier: %s\n", strconv.QuoteToASCII(m.Provider))
		}
		if m.Operation == "add-key" || m.Operation == "add-provider" {
			if m.Lifetime != nil {
				fmt.Fprintf(&b, "Requested upstream lifetime: %d seconds\n", *m.Lifetime)
			} else {
				b.WriteString("Requested upstream lifetime: unspecified\n")
			}
			fmt.Fprintf(&b, "Requested upstream confirmation: %t\n", m.Confirm)
			for _, extension := range m.Extensions {
				fmt.Fprintf(&b, "Upstream constraint extension: %s (passed unchanged)\n", strconv.QuoteToASCII(extension))
			}
		}
		b.WriteString("\nThis changes the real upstream agent shared with other local and forwarded sessions.\n")
		switch m.Operation {
		case "add-key":
			b.WriteString("Adding an existing key can replace its upstream constraints. Key use still requires lend signing permission.\n")
		case "remove-all-keys":
			b.WriteString("This removes every upstream key, including keys hidden by lend.\n")
		case "add-provider":
			b.WriteString("The upstream agent can load local provider code and expose multiple keys.\n")
		case "lock":
			b.WriteString("The requester supplies the passphrase needed to unlock the upstream agent.\n")
		}
		b.WriteString("Private key material, passphrases, and PINs are hidden. Approval applies to this operation once.")
		return b.String()
	}
	if s.Kind == "approval" {
		b.WriteString("A forwarded request is asking for your decision. Nothing runs on this computer.\nOrigin: unverified\n\n")
		s.writeCaller(&b)
		fmt.Fprintf(&b, "Topic: %s\n", strconv.QuoteToASCII(s.Topic))
		if s.Reason != "" {
			fmt.Fprintf(&b, "Reason (requester supplied): %s\n", strconv.QuoteToASCII(s.Reason))
		}
		fmt.Fprintf(&b, "Title (requester supplied): %s\n", strconv.QuoteToASCII(s.Title))
		if s.Details != "" {
			b.WriteString("Details (requester supplied, control and non-ASCII characters escaped):\n")
			for _, line := range strings.Split(s.Details, "\n") {
				b.WriteString("  " + escapeLine(line) + "\n")
			}
		}
		b.WriteString("\nApproval answers this request once. The requester decides what the answer allows.")
		return b.String()
	}
	if s.Kind == "ssh-sign" {
		b.WriteString("A forwarded request wants to sign data with an SSH key.\nOrigin: unverified\n\n")
		s.writeCaller(&b)
		if s.KeyLabel != "" {
			fmt.Fprintf(&b, "Local key label: %s\n", strconv.QuoteToASCII(s.KeyLabel))
		}
		fmt.Fprintf(&b, "Key fingerprint: %s\nKey type: %s\nPurpose: %s\n", strconv.QuoteToASCII(s.KeyFingerprint), strconv.QuoteToASCII(s.KeyType), strconv.QuoteToASCII(s.SigningPurpose))
		if s.SigningNamespace != "" {
			fmt.Fprintf(&b, "SSHSIG namespace: %s\n", strconv.QuoteToASCII(s.SigningNamespace))
		}
		fmt.Fprintf(&b, "Signing payload: %d bytes\nPayload digest: %s\nSignature flags: %d\n\n", s.SigningBytes, strconv.QuoteToASCII(s.SigningDigest), s.SigningFlags)
		if s.Lease == nil {
			b.WriteString("Approval allows this signature once. ")
		} else {
			b.WriteString("Allow once authorizes this signature. Allow lease authorizes the displayed scope. ")
		}
		b.WriteString("The upstream agent can require additional approval.\nThe request does not establish a verified destination or explain why access is needed.")
		return b.String()
	}
	b.WriteString("A forwarded request wants to run a command on this computer.\nOrigin: unverified\n\n")
	s.writeCaller(&b)
	if s.Reason != "" {
		fmt.Fprintf(&b, "Reason (requester supplied): %s\n\n", strconv.QuoteToASCII(s.Reason))
	}
	fmt.Fprintf(&b, "Executable: %s\nDirectory: %s\nArguments (one per line):\n", strconv.QuoteToASCII(s.Executable), strconv.QuoteToASCII(s.Directory))
	for i, arg := range s.Args {
		fmt.Fprintf(&b, "  [%d] %s\n", i, strconv.QuoteToASCII(arg))
	}
	b.WriteString("\nThe command receives this computer's environment. Its output is sent to the requester.\nStdin comes from the requester and can contain additional instructions.")
	return b.String()
}

// escapeLine keeps quotes and backslashes readable so JSON and shell text display as written.
func escapeLine(line string) string {
	var b strings.Builder
	for _, r := range line {
		switch {
		case r == '\t':
			b.WriteString("    ")
		case r < 0x20 || r == 0x7f || r > 0x7e:
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s Summary) writeCaller(b *strings.Builder) {
	if s.RequestID != "" {
		fmt.Fprintf(b, "Local request ID: %s\n", strconv.QuoteToASCII(s.RequestID))
	}
	if s.Session != "" {
		fmt.Fprintf(b, "Local session: %s\n", strconv.QuoteToASCII(s.Session))
	}
	if s.Lease != nil {
		fmt.Fprintf(b, "Optional approval lease: %s, %d uses including this request.\nScope: %s\nDisconnect, device lock, or revocation expires the grant.\n\n", strconv.QuoteToASCII(s.Lease.Duration), s.Lease.Uses, strconv.QuoteToASCII(s.Lease.Scope))
	}
	if len(s.Credentials) > 0 {
		b.WriteString("Credentials injected locally after approval (values hidden):\n")
		for _, name := range sortedCredentialNames(s.Credentials) {
			fmt.Fprintf(b, "  %s from %s\n", strconv.QuoteToASCII(name), strconv.QuoteToASCII(s.Credentials[name]))
		}
		b.WriteString("The approved command can read these values and include them in its output.\n\n")
	}
	if s.Peer != nil {
		b.WriteString("Local socket peer (kernel-reported at connection):\n")
		if s.Peer.PID > 0 {
			fmt.Fprintf(b, "  PID: %d\n", s.Peer.PID)
		}
		if s.Peer.UID != nil {
			fmt.Fprintf(b, "  UID: %d\n", *s.Peer.UID)
		}
		if s.Peer.Process != "" {
			fmt.Fprintf(b, "  Process (local lookup): %s\n", strconv.QuoteToASCII(s.Peer.Process))
		}
		b.WriteString("  Forwarded connections identify the laptop's SSH process here.\n\n")
	}
	if s.Caller == nil {
		b.WriteString("Caller details: unavailable\n\n")
	} else {
		c := s.Caller
		b.WriteString("Caller (requester supplied, unverified):\n")
		for _, field := range []struct{ name, value string }{
			{"Interface", c.Source}, {"Host", c.Host}, {"User", c.User}, {"Executable", c.Executable}, {"Parent process", c.ParentProcess},
			{"Working directory", c.Directory}, {"SSH connection", c.SSHConnection}, {"MCP client", c.ClientName}, {"MCP client version", c.ClientVersion}, {"Tool", c.Tool}, {"Request ID", c.RequestID},
		} {
			if field.value != "" {
				fmt.Fprintf(b, "  %s: %s\n", field.name, strconv.QuoteToASCII(field.value))
			}
		}
		if c.UID != nil {
			fmt.Fprintf(b, "  UID: %d\n", *c.UID)
		}
		if c.PID > 0 {
			fmt.Fprintf(b, "  PID: %d\n", c.PID)
		}
		if c.ParentPID > 0 {
			fmt.Fprintf(b, "  Parent PID: %d\n", c.ParentPID)
		}
		b.WriteByte('\n')
	}
	if len(s.Bindings) > 0 {
		b.WriteString("SSH session hints (upstream accepted, unverified by lend):\n")
		for _, binding := range s.Bindings {
			mode := "authentication"
			if binding.Forwarding {
				mode = "forwarding"
			}
			fmt.Fprintf(b, "  %s host key: %s\n", mode, strconv.QuoteToASCII(binding.Fingerprint))
		}
		if s.OmittedBindings > 0 {
			fmt.Fprintf(b, "  Additional bindings omitted: %d\n", s.OmittedBindings)
		}
		b.WriteByte('\n')
	}
}

type Approver func(context.Context, Summary) error

func New(mode string) (Approver, error) {
	decide, err := NewDecider(mode)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, s Summary) error {
		s.Lease = nil
		_, err := decide(ctx, s)
		return err
	}, nil
}
