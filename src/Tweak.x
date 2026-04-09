/*
 * WiFi Fix Old iOS — WPA2/WPA3 Transitional Mode Fix for iOS 9.x–12.x
 *
 * Problem: Older iOS wifid cannot connect to WPA2/WPA3 transitional networks.
 * The RSN IE parser extracts all AKM suite selectors, including SAE (type 8)
 * which iOS 10 doesn't understand. Two downstream functions break:
 *   1. Security type evaluator picks the highest AKM (8), fails the range
 *      check (1-6), and marks the network security as unknown (0xFFFF).
 *   2. The association RSN element builder also selects AKM 8, hits the
 *      default switch case, and aborts with error -0xF3C.
 *
 * Fix: Hook the RSN IE parser and strip unknown AKM types (>= 7) from the
 * IE_KEY_RSN_AUTHSELS array after parsing. All downstream code then only
 * sees AKMs it understands (1-6), allowing normal WPA2-PSK association.
 *
 * The hook target is found dynamically by decoding ARM instruction sequences
 * (movw/movt on Thumb-2, adrp/add on AArch64) to locate code that references
 * the "IE_KEY_RSN_VERSION" and "IE_KEY_RSN_AUTHSELS" CFString constants.
 */

#include <substrate.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/dyld.h>
#include <syslog.h>

#include "disasm.h"

#define MAX_KNOWN_AKM 6
#define TAG "WiFiFixOldiOS"

/* Heuristic thresholds — validated against wifid from iOS 9.3.6, 10.3.4, 12.5.7.
 * VERSION_MAX_OFFSET: The RSN IE parser references IE_KEY_RSN_VERSION early
 * (observed: +0xC6 .. +0x104), while _performAssociation references it much
 * later (+0x402 .. +0x4CC).  A 0x200 cutoff cleanly separates them.
 * FUNC_BODY_RANGE: Maximum range from function start to scan for secondary
 * string references (AUTHSELS observed at +0x30A .. +0x3CC). */
#define VERSION_MAX_OFFSET  0x200
#define FUNC_BODY_RANGE     0x800

/* ── Dynamic function locator ── */

static void *findRSN_IE_Parser(void) {
    const mach_header_t *header = (const mach_header_t *)_dyld_get_image_header(0);
    if (!header) {
        syslog(LOG_ERR, TAG ": could not get main image header");
        return NULL;
    }
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);

    region_t text, cstring, cfstring;
    if (!findSection(header, slide, "__TEXT", "__text",    &text)    ||
        !findSection(header, slide, "__TEXT", "__cstring", &cstring) ||
        !findSection(header, slide, "__DATA", "__cfstring", &cfstring)) {
        syslog(LOG_ERR, TAG ": required Mach-O sections not found");
        return NULL;
    }

    uintptr_t ver_cf  = resolveCFString(&cstring, &cfstring, "IE_KEY_RSN_VERSION");
    uintptr_t auth_cf = resolveCFString(&cstring, &cfstring, "IE_KEY_RSN_AUTHSELS");
    if (!ver_cf || !auth_cf) {
        syslog(LOG_ERR, TAG ": RSN IE key CFStrings not found");
        return NULL;
    }

    syslog(LOG_NOTICE, TAG ": VERSION cfstr=%p  AUTHSELS cfstr=%p",
           (void *)ver_cf, (void *)auth_cf);

    /* Scan for code references to VERSION, then verify it's the parser:
     *   - VERSION must be near the function start (≤ VERSION_MAX_OFFSET)
     *   - AUTHSELS must also be referenced within the same function body
     * This distinguishes the RSN IE parser from _performAssociation, which
     * also references both strings but much deeper into its body. */
    uintptr_t ref = 0;
    while ((ref = findCodeRef(&text, ver_cf, ref)) != 0) {
        uintptr_t func = findFuncStart(ref, text.addr);
        if (!func || ref - func > VERSION_MAX_OFFSET) continue;

        region_t body = { func, FUNC_BODY_RANGE };
        if (!findCodeRef(&body, auth_cf, 0)) continue;

        syslog(LOG_NOTICE, TAG ": found parseRSN_IE at %p (VERSION +0x%lx)",
               (void *)func, (unsigned long)(ref - func));
        return FUNC_PTR(func);
    }

    syslog(LOG_ERR, TAG ": could not locate parseRSN_IE");
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
        CFNumberRef num = (CFNumberRef)CFArrayGetValueAtIndex(authSels, i);
        int32_t akm = 0;
        if (CFNumberGetValue(num, kCFNumberSInt32Type, &akm)
            && akm >= 1 && akm <= MAX_KNOWN_AKM) {
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

/* int parseRSN_IE(const char *rawIE, int totalLen, CFMutableDictionaryRef output) */
typedef int (*rsn_ie_parser_t)(const char *, int, CFMutableDictionaryRef);
static rsn_ie_parser_t orig_parseRSN_IE;

static int hooked_parseRSN_IE(const char *rawIE, int totalLen, CFMutableDictionaryRef output) {
    int ret = orig_parseRSN_IE(rawIE, totalLen, output);
    if (ret != 0 || !output) return ret;

    /* The RSN_IE dict is created as CFMutableDictionary by the parser */
    CFDictionaryRef rsnIE = CFDictionaryGetValue(output, CFSTR("RSN_IE"));
    if (rsnIE) {
        filterAuthSels((CFMutableDictionaryRef)rsnIE);
    }
    return ret;
}

/* ── Constructor ── */

%ctor {
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
