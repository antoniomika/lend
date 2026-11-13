//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <LocalAuthenticationEmbeddedUI/LocalAuthenticationEmbeddedUI.h>

enum { lendInlineOnce = 1001, lendInlineLease = 1002, lendInlineFailed = 1003 };

int lend_auth_available(int biometric) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        LAPolicy policy = biometric ? LAPolicyDeviceOwnerAuthenticationWithBiometrics : LAPolicyDeviceOwnerAuthentication;
        BOOL available = [context canEvaluatePolicy:policy error:NULL];
        [context invalidate];
        return available ? 1 : 0;
    }
}

static NSScrollView *lend_request_view(const char *message, NSRect frame) {
    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:frame];
    scroll.hasVerticalScroller = YES;
    scroll.hasHorizontalScroller = YES;
    NSTextView *text = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, frame.size.width - 20, frame.size.height)];
    text.editable = NO;
    text.font = [NSFont userFixedPitchFontOfSize:12];
    text.string = [NSString stringWithUTF8String:message];
    text.verticallyResizable = YES;
    scroll.documentView = text;
    return scroll;
}

static void lend_stop_modal(NSInteger code) {
    [NSApp stopModalWithCode:code];
    // stopModal outside an event handler takes effect after the next event.
    NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:0 context:nil subtype:0 data1:0 data2:0];
    [NSApp postEvent:wake atStart:YES];
}

// Touch ID runs inside the request dialog, so a matching touch is the approval.
static int lend_approve_inline(const char *message, int lease) API_AVAILABLE(macos(12.0)) {
    LAContext *context = [[LAContext alloc] init];
    context.touchIDAuthenticationAllowableReuseDuration = 0;
    context.localizedFallbackTitle = @"";
    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:NULL]) {
        [context invalidate];
        return 0;
    }

    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Approve this lend request?";
    alert.informativeText = lease ? @"Review the full request. Touch ID allows this operation once, or the lease if selected." : @"Review the full request. Touch ID allows this operation once.";
    [alert addButtonWithTitle:@"Deny"];

    CGFloat width = 680, scrollHeight = 360, y = 0;
    NSView *container = [[NSView alloc] initWithFrame:NSZeroRect];
    LAAuthenticationView *touch = [[LAAuthenticationView alloc] initWithContext:context];
    touch.frame = NSMakeRect(0, y, 40, 40);
    [container addSubview:touch];
    NSTextField *hint = [NSTextField labelWithString:@"Touch ID to allow"];
    hint.frame = NSMakeRect(50, y + 10, width - 50, 20);
    [container addSubview:hint];
    y += 48;
    NSButton *leaseBox = nil;
    if (lease) {
        leaseBox = [NSButton checkboxWithTitle:@"Allow the lease shown above" target:nil action:nil];
        leaseBox.frame = NSMakeRect(0, y, width, 20);
        [container addSubview:leaseBox];
        y += 28;
    }
    [container addSubview:lend_request_view(message, NSMakeRect(0, y, width, scrollHeight))];
    container.frame = NSMakeRect(0, 0, width, y + scrollHeight);
    alert.accessoryView = container;

    __block BOOL done = NO;
    // The delay keeps a finger already resting on the sensor from approving a request before it is read.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (done) { return; }
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:@"approve the lend request"
                reply:^(BOOL success, NSError *authError) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        if (done) { return; }
                        done = YES;
                        NSInteger code = lendInlineFailed;
                        if (success) {
                            code = leaseBox != nil && leaseBox.state == NSControlStateValueOn ? lendInlineLease : lendInlineOnce;
                        }
                        lend_stop_modal(code);
                    });
                }];
    });
    NSModalResponse choice = [alert runModal];
    done = YES;
    [context invalidate];
    if (choice == lendInlineOnce) { return 1; }
    if (choice == lendInlineLease) { return 2; }
    return 0;
}

int lend_approve(const char *message, int requirement, int lease, int inline_biometric) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [NSApp activateIgnoringOtherApps:YES];
        if (inline_biometric && requirement == 2) {
            if (@available(macOS 12.0, *)) {
                return lend_approve_inline(message, lease);
            }
        }
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Approve this lend request?";
        alert.informativeText = lease ? @"Review the full request and optional lease scope." : @"Review the full request. Allow applies to this operation once.";
        [alert addButtonWithTitle:@"Deny"];
        [alert addButtonWithTitle:@"Allow once"];
        if (lease) { [alert addButtonWithTitle:@"Allow lease"]; }
        alert.accessoryView = lend_request_view(message, NSMakeRect(0, 0, 680, 360));
        NSModalResponse choice = [alert runModal];
        int decision = choice == NSAlertSecondButtonReturn ? 1 : (lease && choice == NSAlertThirdButtonReturn ? 2 : 0);
        if (!decision) { return 0; }
        if (requirement == 0) { return decision; }

        LAContext *context = [[LAContext alloc] init];
        context.touchIDAuthenticationAllowableReuseDuration = 0;
        LAPolicy policy = requirement == 2 ? LAPolicyDeviceOwnerAuthenticationWithBiometrics : LAPolicyDeviceOwnerAuthentication;
        if (requirement == 2) { context.localizedFallbackTitle = @""; }
        NSError *error = nil;
        if (![context canEvaluatePolicy:policy error:&error]) { return 0; }
        __block BOOL finished = NO;
        __block BOOL allowed = NO;
        // macOS shows this as "lend is trying to <reason>." and adds the period itself.
        [context evaluatePolicy:policy
                localizedReason:@"approve the request you just reviewed"
                reply:^(BOOL success, NSError *authError) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        allowed = success;
                        finished = YES;
                    });
                }];
        while (!finished) {
            [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        }
        [context invalidate];
        return allowed ? decision : 0;
    }
}
