//go:build darwin && !cgo

package device

import (
	"context"
	"errors"
)

type State struct {
	Unlocked bool
	Changed  bool
}

func Check(context.Context) (State, error) {
	return State{}, errors.New("desktop lock tracking requires cgo on macOS")
}
