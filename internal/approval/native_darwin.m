//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>

int lend_auth_available(int biometric) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        LAPolicy policy = biometric ? LAPolicyDeviceOwnerAuthenticationWithBiometrics : LAPolicyDeviceOwnerAuthentication;
        BOOL available = [context canEvaluatePolicy:policy error:NULL];
        [context invalidate];
        return available ? 1 : 0;
    }
}

int lend_approve(const char *message, int requirement, int lease) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [NSApp activateIgnoringOtherApps:YES];
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Approve this lend request?";
        alert.informativeText = lease ? @"Review the full request and optional lease scope." : @"Review the full request. Allow applies to this operation once.";
        [alert addButtonWithTitle:@"Deny"];
        [alert addButtonWithTitle:@"Allow once"];
        if (lease) { [alert addButtonWithTitle:@"Allow lease"]; }
        NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 680, 360)];
        scroll.hasVerticalScroller = YES;
        scroll.hasHorizontalScroller = YES;
        NSTextView *text = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, 660, 360)];
        text.editable = NO;
        text.font = [NSFont userFixedPitchFontOfSize:12];
        text.string = [NSString stringWithUTF8String:message];
        text.verticallyResizable = YES;
        scroll.documentView = text;
        alert.accessoryView = scroll;
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
        [context evaluatePolicy:policy
                localizedReason:@"Approve the request you just reviewed in lend."
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
