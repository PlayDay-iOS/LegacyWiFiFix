/*
 * Legacy WiFi Fix -- RSN IE AKM-selection bug fix for iOS 3.x-12.x
 *
 * The bug: iOS wifid / WiFiManager iterates IE_KEY_RSN_AUTHSELS tracking
 * the "best" AKM.  When either the running best or a new candidate is
 * outside the table-driven range, the comparison falls back to raw value,
 * so a later unknown AKM (e.g. SAE = 8) overwrites an earlier known one
 * (e.g. PSK = 2).  The switch on the selected AKM then hits `default:`
 * and returns 0xFFFFF0C4 (-0xF3C), rejecting any network that advertises
 * an unrecognised AKM alongside a supported one -- WPA2/WPA3 transitional
 * being the common case on modern APs.
 *
 * The supported AKM range depends on the iOS version (verified via
 * Ghidra against stock wifid/WiFiManager -- the switch over the
 * selected AKM value inside _performAssociation):
 *
 *   iOS 3.x - 5.x : switch handles AKMs 1..2  (FT not yet shipped)
 *   iOS 6.x - 7.x : switch handles AKMs 1..4  (FT added)
 *   iOS 8.x - 12.x: switch handles AKMs 1..6  (SHA256 variants added)
 *
 * iOS 12.5.x added an explicit `(akm - 1) < 6` guard inside
 * _performAssociation's RSN loop, but a sibling function (FUN_100170a60
 * in 12.5.8 wifid) still uses the unguarded raw-value pattern and rejects
 * via its own 1..6 switch.  The tweak is therefore still needed on iOS 12.
 *
 * The fix: hook parseRSN_IE and drop AKMs outside 1..MAX_KNOWN_AKM from
 * IE_KEY_RSN_AUTHSELS before downstream code iterates it.  MAX_KNOWN_AKM
 * is picked at load time from kCFCoreFoundationVersionNumber: 2 on
 * iOS <= 5, 4 on iOS 6..7, 6 on iOS >= 8.
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
 *
 * Host process: on iOS 5+ the parser lives in /usr/sbin/wifid.  On iOS 3-4
 * it lives in WiFiManager.bundle, a SystemConfiguration plugin that configd
 * loads after startup, so the image scan runs from a dyld add-image callback.
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

/* -- RSN IE AUTHSELS filter --
 *
 * filterAuthSels runs once per scanned BSS, which in dense RF environments
 * (airports, conferences) can mean hundreds of calls per second.  To keep
 * syslog usable we log the first LOG_BUDGET filter events verbosely, then
 * suppress until the next reset interval.  Counters are not thread-safe but
 * parseRSN_IE is called from the WiFi serial dispatch queue, so all calls
 * here are serialized.
 */

#define LOG_BUDGET 16

static unsigned g_log_used = 0;

static inline bool logBudgetOk(void) {
    if (g_log_used < LOG_BUDGET) { g_log_used++; return true; }
    if (g_log_used == LOG_BUDGET) {
        syslog(LOG_NOTICE, TAG ": further per-BSS filter logs suppressed");
        g_log_used++;
    }
    return false;
}

static void filterAuthSels(CFMutableDictionaryRef rsnIE) {
    CFArrayRef authSels = CFDictionaryGetValue(rsnIE, CFSTR("IE_KEY_RSN_AUTHSELS"));
    if (!authSels) return;

    CFIndex count = CFArrayGetCount(authSels);
    if (count == 0) return;

    CFMutableArrayRef filtered = CFArrayCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (!filtered) return;

    bool didFilter = false;
    bool logOk = logBudgetOk();
    for (CFIndex i = 0; i < count; i++) {
        CFTypeRef elem = CFArrayGetValueAtIndex(authSels, i);
        if (!elem || CFGetTypeID(elem) != CFNumberGetTypeID()) {
            didFilter = true;
            if (logOk)
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
            if (logOk)
                syslog(LOG_NOTICE, TAG ": stripped unknown AKM %d from RSN IE", akm);
        }
    }

    if (didFilter && CFArrayGetCount(filtered) > 0) {
        CFDictionarySetValue(rsnIE, CFSTR("IE_KEY_RSN_AUTHSELS"), filtered);
        if (logOk)
            syslog(LOG_NOTICE, TAG ": kept %ld of %ld AKM selectors",
                   CFArrayGetCount(filtered), count);
    } else if (didFilter && logOk) {
        syslog(LOG_WARNING, TAG ": all AKMs were unknown -- leaving unmodified");
    }

    CFRelease(filtered);
}

/* -- Hook -- */

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

/* -- Image-load callback --
 *
 * dyld invokes this once for every image already loaded at registration
 * time, then again for each image loaded later.  The second case matters on
 * iOS 3-4, where configd dlopen()s WiFiManager.bundle as a plugin well after
 * the tweak's constructor has run.  dyld serializes these callbacks under
 * its own lock, so the plain flag needs no further synchronization.
 */

static bool g_hooked = false;

static void onImageAdded(const struct mach_header *mh, intptr_t slide) {
    if (g_hooked) return;

    uintptr_t func = findRSN_IE_ParserInImage((const mach_header_t *)mh, slide);
    if (!func) return;

    g_hooked = true;
    void *target = FUNC_PTR(func);
    MSHookFunction(target,
                   (void *)hooked_parseRSN_IE,
                   (void **)&orig_parseRSN_IE);
    syslog(LOG_NOTICE, TAG ": hook installed at %p", target);
}

/* -- Constructor --
 *
 * Fail-safe properties:
 *   1. If no loaded image contains the parser, no MSHookFunction call is made
 *      and the host runs unmodified -- WiFi simply behaves as the stock OS.
 *   2. If the finder returned a wrong address, MSHookFunction would patch
 *      arbitrary code and wifid would crash on first invocation.  launchd
 *      back-off (3 crashes in 60s) then stops respawning it; WiFi breaks
 *      until the package is removed, but the device boots normally --
 *      no boot loop, since wifid is not on the boot critical path.
 *   3. The locator is heavily constrained (two distinct CFString refs in a
 *      narrow byte window), making a wrong-address result extremely unlikely
 *      across the verified iOS 3.x-12.x corpus.
 */

%ctor {
    if (IS_IOS_OR_NEWER(iOS_8_0)) {
        g_max_known_akm = 6;
    } else if (IS_IOS_OR_NEWER(iOS_6_0)) {
        g_max_known_akm = 4;
    } else {
        g_max_known_akm = 2;
    }
    syslog(LOG_NOTICE, TAG ": CFVersion=%.1f -> max known AKM = %d",
           kCFCoreFoundationVersionNumber, g_max_known_akm);

    _dyld_register_func_for_add_image(onImageAdded);
}
