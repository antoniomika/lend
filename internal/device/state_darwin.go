//go:build darwin && cgo

package device

/*
#cgo LDFLAGS: -framework ApplicationServices
#include <ApplicationServices/ApplicationServices.h>
#include <notify.h>
static int lend_device_state(int *changed) {
 static int token = -1;
 if (token == -1 && notify_register_check("com.apple.screenIsLocked", &token) != NOTIFY_STATUS_OK) { return -1; }
 int event = 0;
 if (notify_check(token, &event) != NOTIFY_STATUS_OK) { return -1; }
 *changed = event;
 CFDictionaryRef session = CGSessionCopyCurrentDictionary();
 if (!session) { return -1; }
 CFTypeRef console = CFDictionaryGetValue(session, kCGSessionOnConsoleKey);
 CFTypeRef logged = CFDictionaryGetValue(session, kCGSessionLoginDoneKey);
 CFTypeRef locked = CFDictionaryGetValue(session, CFSTR("CGSSessionScreenIsLocked"));
 int unlocked = console == kCFBooleanTrue && logged == kCFBooleanTrue && locked != kCFBooleanTrue;
 CFRelease(session);
 return unlocked;
}
*/
import "C"

import (
	"context"
	"errors"
	"sync"
)

type State struct {
	Unlocked bool
	Changed  bool
}

var stateMu sync.Mutex

func Check(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	var changed C.int
	value := C.lend_device_state(&changed)
	if value < 0 {
		return State{}, errors.New("desktop lock state is unavailable")
	}
	return State{Unlocked: value == 1, Changed: changed != 0}, nil
}
