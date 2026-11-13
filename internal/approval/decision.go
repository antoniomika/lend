package approval

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
)

type LeaseOffer struct {
	Duration string
	Uses     int
	Scope    string
}
type Decision struct{ Lease bool }
type Decider func(context.Context, Summary) (Decision, error)

func NewDecider(mode string) (Decider, error) {
	if mode != "auto" && mode != "terminal" {
		return nil, errors.New("approval mode must be auto or terminal")
	}
	return func(ctx context.Context, s Summary) (Decision, error) {
		if mode == "terminal" {
			if s.Requirement == "biometric" || s.Requirement == "authenticate" {
				return Decision{}, errors.New("terminal approval cannot satisfy required device authentication")
			}
			return terminalDecision(ctx, s)
		}
		return nativeDecision(ctx, s)
	}, nil
}

func sortedCredentialNames(credentials map[string]string) []string {
	names := make([]string, 0, len(credentials))
	for name := range credentials {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func terminalDecision(ctx context.Context, s Summary) (Decision, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Decision{}, errors.New("local approval requires a controlling terminal or desktop session")
	}
	defer tty.Close()
	stop := context.AfterFunc(ctx, func() { tty.Close() })
	defer stop()
	var nonce [3]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Decision{}, err
	}
	once := fmt.Sprintf("allow %x", nonce)
	lease := fmt.Sprintf("lease %x", nonce)
	prompt := "Type " + once + " to allow once"
	if s.Lease != nil {
		prompt += ", or " + lease + " to allow the displayed lease"
	}
	if _, err := fmt.Fprintf(tty, "\n%s\n\n%s: ", s.String(), prompt); err != nil {
		return Decision{}, err
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return Decision{}, err
	}
	line = strings.TrimSpace(line)
	if line == once {
		return Decision{}, ctx.Err()
	}
	if s.Lease != nil && line == lease {
		return Decision{Lease: true}, ctx.Err()
	}
	return Decision{}, errors.New("request denied")
}
