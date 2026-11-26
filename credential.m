#import <AppKit/AppKit.h>
#import <CoreWLAN/CoreWLAN.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

// Only the explicit --connect-saved path asks for the saved password for the selected SSID.
size_t calnet_secret(bool saved, const uint8_t *name, size_t length, uint8_t out[65]) {
    @autoreleasepool {
        NSString *secret = nil;
        NSData *ssid = [NSData dataWithBytes:name length:length];
        NSString *display = [[NSString alloc] initWithData:ssid encoding:NSUTF8StringEncoding];
        if (!display) return 0;
        if (saved) {
            OSStatus status = CWKeychainFindWiFiPassword(kCWKeychainDomainSystem, ssid, &secret);
            if (status == errSecItemNotFound)
                status = CWKeychainFindWiFiPassword(kCWKeychainDomainUser, ssid, &secret);
            if (status != errSecSuccess || !secret) {
                fprintf(stderr, "Selected Wi-Fi Keychain item returned %d\n", (int)status);
                return 0;
            }
        } else {
            [NSApplication sharedApplication];
            [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
            NSAlert *dialog = [[NSAlert alloc] init];
            dialog.messageText = [NSString stringWithFormat:@"Join %@ with the USB Wi-Fi dongle",display];
            dialog.informativeText = @"Enter this network’s Wi-Fi password for this connection.";
            NSSecureTextField *field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0,0,320,24)];
            dialog.accessoryView = field;
            [dialog addButtonWithTitle:@"Join"];
            [dialog addButtonWithTitle:@"Cancel"];
            dialog.window.initialFirstResponder = field;
            [NSApp activate];
            if ([dialog runModal] != NSAlertFirstButtonReturn) return 0;
            secret = [field.stringValue copy];
            field.stringValue = @"";
        }
        NSUInteger n = [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (n < 8 || n > 64 || ![secret getCString:(char *)out maxLength:65 encoding:NSUTF8StringEncoding])
            return 0;
        return n;
    }
}
