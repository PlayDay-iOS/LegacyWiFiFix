/*
 * WiFi Fix Old iOS — RSN IE AKM-selection bug fix for iOS 3.x–12.x
 *
 * The bug: iOS wifid / WiFiManager iterates IE_KEY_RSN_AUTHSELS tracking
 * the "best" AKM.  When either the running best or a new candidate is
 * outside the table-driven range, the comparison falls back to raw value,
 * so a later unknown AKM (e.g. SAE = 8) overwrites an earlier known one
 * (e.g. PSK = 2).  The switch on the selected AKM then hits `default:`
 * and returns 0xFFFFF0C4 (-0xF3C), rejecting any network that advertises
 * an unrecognised AKM alongside a supported one — WPA2/WPA3 transitional
 * being the common case on modern APs.
 *
 * The supported AKM range depends on the iOS version (verified via
 * Ghidra against stock wifid/WiFiManager — the switch over the
 * selected AKM value inside _performAssociation):
 *
 *   iOS 3.x – 5.x : switch handles AKMs 1..2  (FT not yet shipped)
 *   iOS 6.x – 7.x : switch handles AKMs 1..4  (FT added)
 *   iOS 8.x – 12.x: switch handles AKMs 1..6  (SHA256 variants added)
 *
 * iOS 12.5.x added an explicit `(akm - 1) < 6` guard inside
 * _performAssociation's RSN loop, but a sibling function (FUN_100170a60
 * in 12.5.8 wifid) still uses the unguarded raw-value pattern and rejects
 * via its own 1..6 switch.  The tweak is therefore still needed on iOS 12.
 *
 * The fix: hook parseRSN_IE and drop AKMs outside 1..MAX_KNOWN_AKM from
 * IE_KEY_RSN_AUTHSELS before downstream code iterates it.  MAX_KNOWN_AKM
 * is picked at load time from kCFCoreFoundationVersionNumber: 2 on
 * iOS ≤ 5, 4 on iOS 6..7, 6 on iOS ≥ 8.
 *
 * AKM values (IEEE 802.11-2020 Table 9-151):
 *   1 = 802.1X (WPA2-Enterprise)      5 = 802.1X-SHA256
 *   2 = PSK    (WPA2-Personal)        6 = PSK-SHA256
 *   3 = FT-802.1X                     7 = TDLS
 *   4 = FT-PSK                        8 = SAE (WPA3-Personal)
 *
 * The hook target is located dynamically by decoding ARM instruction
 * sequences that reference the "IE_KEY_RSN_VERSION" and
 * "IE_KEY_RSN_AUTHSELS" CFString constants.
 */

#include <substrate.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/dyld.h>
#include <syslog.h>
#include <version.h>           /* Theos: IS_IOS_OR_NEWER, kCFCoreFoundationVersionNumber_iOS_* */

#include "finder.h"

/* Runtime-selected max AKM value.  Populated at %ctor from the OS
 * version (see file header for the per-version table). */
static int g_max_known_akm = 6;

/* ── Dynamic function locator ── */

static void *findRSN_IE_Parser(void) {
    uint32_t count = _dyld_image_count();
    syslog(LOG_NOTICE, TAG ": scanning %u loaded images", count);
    for (uint32_t i = 0; i < count; i++) {
        const mach_header_t *header =
            (const mach_header_t *)_dyld_get_image_header(i);
        if (!header) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const char *name = _dyld_get_image_name(i);

        uintptr_t func = findRSN_IE_ParserInImage(header, slide);
        if (func) {
            syslog(LOG_NOTICE, TAG ": located parser in image %u (%s)",
                   i, name ? name : "(null)");
            return FUNC_PTR(func);
        }
    }
    return NULL;
}

/* ── RSN IE AUTHSELS filter ── */

static void filterAuthSels(CFMutableDictionaryRef rsnIE) {
    CFArrayRef authSels = CFDictionaryGetValue(rsnIE, CFSTR("IE_KEY_RSN_AUTHSELS"));
    if (!authSels) return;

    CFIndex count = CFArrayGetCount(authSels);
    if (count == 0) return;

    CFMutableArrayRef filtered = CFArrayCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (!filtered) return;

    bool didFilter = false;
    for (CFIndex i = 0; i < count; i++) {
        CFTypeRef elem = CFArrayGetValueAtIndex(authSels, i);
        if (!elem || CFGetTypeID(elem) != CFNumberGetTypeID()) {
            didFilter = true;
            syslog(LOG_NOTICE, TAG ": stripped non-CFNumber element from RSN IE");
            continue;
        }
        CFNumberRef num = (CFNumberRef)elem;
        int32_t akm = 0;
        if (CFNumberGetValue(num, kCFNumberSInt32Type, &akm)
            && akm >= 1 && akm <= g_max_known_akm) {
            CFArrayAppendValue(filtered, num);
        } else {
            didFilter = true;
            syslog(LOG_NOTICE, TAG ": stripped unknown AKM %d from RSN IE", akm);
        }
    }

    if (didFilter && CFArrayGetCount(filtered) > 0) {
        CFDictionarySetValue(rsnIE, CFSTR("IE_KEY_RSN_AUTHSELS"), filtered);
        syslog(LOG_NOTICE, TAG ": kept %ld of %ld AKM selectors",
               CFArrayGetCount(filtered), count);
    } else if (didFilter) {
        syslog(LOG_WARNING, TAG ": all AKMs were unknown — leaving unmodified");
    }

    CFRelease(filtered);
}

/* ── Hook ── */

typedef int (*rsn_ie_parser_t)(const char *, int, CFMutableDictionaryRef);
static rsn_ie_parser_t orig_parseRSN_IE;

static int hooked_parseRSN_IE(const char *rawIE, int totalLen,
                               CFMutableDictionaryRef output) {
    int ret = orig_parseRSN_IE(rawIE, totalLen, output);
    if (ret != 0 || !output) return ret;

    CFTypeRef rsnIE = CFDictionaryGetValue(output, CFSTR("RSN_IE"));
    if (rsnIE && CFGetTypeID(rsnIE) == CFDictionaryGetTypeID()) {
        filterAuthSels((CFMutableDictionaryRef)rsnIE);
    }
    return ret;
}

/* ── Constructor ── */

%ctor {
    if (IS_IOS_OR_NEWER(iOS_8_0)) {
        g_max_known_akm = 6;
    } else if (IS_IOS_OR_NEWER(iOS_6_0)) {
        g_max_known_akm = 4;
    } else {
        g_max_known_akm = 2;
    }
    syslog(LOG_NOTICE, TAG ": CFVersion=%.1f → max known AKM = %d",
           kCFCoreFoundationVersionNumber, g_max_known_akm);

    void *target = findRSN_IE_Parser();
    if (!target) {
        syslog(LOG_ERR, TAG ": could not locate RSN IE parser — hook not installed");
        return;
    }

    MSHookFunction(target,
                   (void *)hooked_parseRSN_IE,
                   (void **)&orig_parseRSN_IE);

    syslog(LOG_NOTICE, TAG ": hook installed at %p", target);
}
