package device

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

type State struct {
	Unlocked bool
	Changed  bool
}

func Check(ctx context.Context) (State, error) {
	session := os.Getenv("XDG_SESSION_ID")
	if session == "" {
		return State{}, errors.New("desktop login session is unavailable")
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/loginctl", "show-session", "--property=LockedHint", "--property=Active", "--property=Type", "--property=CanLock", "--", session).Output()
	if err != nil {
		return State{}, err
	}
	return parseState(string(out))
}

func parseState(output string) (State, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = value
		}
	}
	if fields["LockedHint"] != "yes" && fields["LockedHint"] != "no" {
		return State{}, errors.New("desktop lock state is unavailable")
	}
	desktop := fields["Type"] == "x11" || fields["Type"] == "wayland"
	if !desktop || fields["CanLock"] != "yes" {
		return State{}, errors.New("desktop lock tracking is unavailable for this session")
	}
	return State{Unlocked: fields["Active"] == "yes" && fields["LockedHint"] == "no"}, nil
}
