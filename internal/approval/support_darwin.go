//go:build darwin && cgo

package approval

/*
#cgo LDFLAGS: -framework LocalAuthentication
int lend_auth_available(int biometric);
*/
import "C"

func Inspect() Support {
	return Support{Backend: "macOS", Prompt: true, Authentication: C.lend_auth_available(0) == 1, Biometrics: C.lend_auth_available(1) == 1}
}
