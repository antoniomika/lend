//go:build darwin && !cgo

package approval

func Inspect() Support {
	return Support{Backend: "terminal (build has no native macOS support)", Prompt: HasTerminal()}
}
