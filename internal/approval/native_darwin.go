//go:build darwin && cgo

package approval

/*
#cgo LDFLAGS: -framework AppKit -framework LocalAuthentication -framework LocalAuthenticationEmbeddedUI
#include <stdlib.h>
int lend_approve(const char *message, int requirement, const char *lease, int inline_biometric);
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"unsafe"
)

func init() {
	// AppKit must run on the initial thread in the approval helper.
	runtime.LockOSThread()
}

func native(ctx context.Context, s Summary) error {
	_, err := nativeDecision(ctx, s)
	return err
}

func nativeDecision(ctx context.Context, s Summary) (Decision, error) {
	path, err := os.Executable()
	if err != nil {
		return Decision{}, err
	}
	cmd := exec.CommandContext(ctx, path, "_approve")
	data, err := json.Marshal(s)
	if err != nil {
		return Decision{}, err
	}
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if s.Lease != nil && errors.As(err, &exit) && exit.ExitCode() == 2 {
			return Decision{Lease: true}, ctx.Err()
		}
		return Decision{}, errors.New("local approval denied or authentication failed")
	}
	return Decision{}, ctx.Err()
}

func RunHelper() int {
	var summary Summary
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 256*1024)).Decode(&summary); err != nil {
		return 1
	}
	requirement, inline := 1, 0
	switch summary.Requirement {
	case "prompt":
		requirement = 0
	case "biometric", "biometric:separate":
		requirement = 2
	case "biometric:inline":
		requirement, inline = 2, 1
	case "auto", "authenticate", "":
	default:
		return 1
	}
	cstr := C.CString(summary.String())
	defer C.free(unsafe.Pointer(cstr))
	var lease *C.char
	if summary.Lease != nil {
		lease = C.CString(fmt.Sprintf("Allow a lease for %s or %d uses", summary.Lease.Duration, summary.Lease.Uses))
		defer C.free(unsafe.Pointer(lease))
	}
	result := C.lend_approve(cstr, C.int(requirement), lease, C.int(inline))
	if result == 2 {
		return 2
	}
	if result == 1 {
		return 0
	}
	return 1
}
