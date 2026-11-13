//go:build darwin && !cgo

package approval

import (
	"context"
	"errors"
)

func native(context.Context, Summary) error {
	return errors.New("native macOS approval requires a build with CGO_ENABLED=1; use --approval=terminal for terminal approval")
}

func nativeDecision(ctx context.Context, s Summary) (Decision, error) {
	return Decision{}, native(ctx, s)
}

func RunHelper() int { return 1 }
