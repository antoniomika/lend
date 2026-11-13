package approval

import (
	"os"
	"syscall"
)

type Support struct {
	Backend        string `json:"backend"`
	Prompt         bool   `json:"prompt"`
	Authentication bool   `json:"authentication"`
	Biometrics     bool   `json:"biometrics"`
}

func HasTerminal() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	tty.Close()
	return true
}
