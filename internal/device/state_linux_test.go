package device

import "testing"

func TestDesktopStateRequiresActiveLockCapableSession(t *testing.T) {
	for _, test := range []struct {
		input           string
		unlocked, valid bool
	}{
		{"LockedHint=no\nActive=yes\nCanLock=yes\nType=wayland\n", true, true},
		{"LockedHint=yes\nActive=yes\nCanLock=yes\nType=x11\n", false, true},
		{"LockedHint=no\nActive=no\nCanLock=yes\nType=wayland\n", false, true},
		{"LockedHint=no\nActive=yes\nCanLock=no\nType=wayland\n", false, false},
		{"LockedHint=no\nActive=yes\nCanLock=yes\nType=tty\n", false, false},
		{"Active=yes\nType=wayland\n", false, false},
	} {
		state, err := parseState(test.input)
		if state.Unlocked != test.unlocked || (err == nil) != test.valid {
			t.Fatalf("state=%+v err=%v for %q", state, err, test.input)
		}
	}
}
