package approval

import (
	"os"
	"os/exec"
)

func Inspect() Support {
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		if _, err := exec.LookPath("zenity"); err == nil {
			return Support{Backend: "zenity", Prompt: true}
		}
	}
	return Support{Backend: "terminal", Prompt: HasTerminal()}
}
