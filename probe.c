// Count exactly matching USB devices without opening interfaces or touching registers.
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
int main(void) {
    CFMutableDictionaryRef match = IOServiceMatching("IOUSBHostDevice");
    if (!match) return 1;
    int vendor = 0x0bda, product = 0xb812;
    CFNumberRef vid = CFNumberCreate(NULL, kCFNumberIntType, &vendor);
    CFNumberRef pid = CFNumberCreate(NULL, kCFNumberIntType, &product);
    CFDictionarySetValue(match, CFSTR("idVendor"), vid);
    CFDictionarySetValue(match, CFSTR("idProduct"), pid);
    CFRelease(vid);
    CFRelease(pid);
    io_iterator_t devices;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &devices) != KERN_SUCCESS) return 1;
    int count = 0;
    io_service_t device;
    while ((device = IOIteratorNext(devices))) {
        count++;
        IOObjectRelease(device);
    }
    IOObjectRelease(devices);
    if (count != 1) fprintf(stderr, "Expected one USB 0bda:b812 adapter, found %d.\n", count);
    return count == 1 ? 0 : 1;
}
