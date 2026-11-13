package approval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxCannotDowngradeAuthentication(t *testing.T) {
	for _, requirement := range []string{"biometric", "authenticate"} {
		if err := native(context.Background(), Summary{Requirement: requirement}); err == nil {
			t.Fatalf("Linux satisfied %s without a backend", requirement)
		}
	}
}

func TestDesktopLeaseChoiceIsExplicitAndCannotTurnCancelIntoApproval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zenity")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("DISPLAY", ":fixture")
	t.Setenv("ZENITY_CANCEL", "0")
	for _, test := range []struct {
		name, output, code    string
		offer, lease, allowed bool
	}{
		{"once", "", "0", true, false, true},
		{"lease", "Allow lease\\n", "2", true, true, true},
		{"cancel", "", "1", true, false, false},
		{"unsolicited", "Allow lease\\n", "2", false, false, false},
		{"wrong-exit", "Allow lease\\n", "1", true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := "#!/bin/sh\ncat >/dev/null\n[ \"$ZENITY_CANCEL\" = 1 ] || exit 99\nprintf '" + test.output + "'\nexit " + test.code + "\n"
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			summary := Summary{Requirement: "prompt"}
			if test.offer {
				summary.Lease = &LeaseOffer{Duration: "1m", Uses: 3, Scope: "fixture"}
			}
			decision, err := nativeDecision(context.Background(), summary)
			if (err == nil) != test.allowed || decision.Lease != test.lease {
				t.Fatalf("decision=%+v err=%v", decision, err)
			}
		})
	}
}
