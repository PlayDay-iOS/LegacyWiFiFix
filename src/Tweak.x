/*
 * WiFi Fix Old iOS — WPA2/WPA3 Transitional Mode Fix for iOS 10.x
 *
 * Problem: iOS 10's wifid cannot connect to WPA2/WPA3 transitional networks.
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
 * The hook target is found dynamically via byte-pattern scanning of the
 * function's distinctive prologue + error-code load sequence.
 */

#include <substrate.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <syslog.h>
#include <stdint.h>

#define MAX_KNOWN_AKM 6
#define TAG "WiFiFixOldiOS"

/* ── Mach-O helpers ── */

#ifdef __LP64__
typedef struct mach_header_64    mach_header_t;
typedef struct section_64        section_t;
typedef struct segment_command_64 segment_command_t;
#define LC_SEGMENT_T LC_SEGMENT_64
#else
typedef struct mach_header       mach_header_t;
typedef struct section           section_t;
typedef struct segment_command   segment_command_t;
#define LC_SEGMENT_T LC_SEGMENT
#endif

static inline bool streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static bool findSection(const mach_header_t *header, intptr_t slide,
                        const char *segname, const char *sectname,
                        uintptr_t *out_addr, size_t *out_size) {
    uintptr_t cursor = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_T) {
            segment_command_t *seg = (segment_command_t *)cursor;
            if (streq(seg->segname, segname)) {
                section_t *sect = (section_t *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (streq(sect[j].sectname, sectname)) {
                        *out_addr = sect[j].addr + slide;
                        *out_size = sect[j].size;
                        return true;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return false;
}

/* ── Byte pattern scanner ── */

/*
 * RSN IE parser signature (ARM Thumb-2, iOS 10.x wifid):
 *
 *   push.w  {r8, r10, r11}     = 2D E9 00 0D
 *   sub     sp, #0x88           = A2 B0
 *   movw    r6, #0xF0C3         = 4F F2 C3 06     ← loads lo16(-0xF3D)
 *   movt    r6, #0xFFFF         = CF F6 FF 76     ← loads hi16(-0xF3D)
 *
 * This 14-byte sequence starts 4 bytes into the function (after push {r4-r7,lr}
 * and add r7,sp,#imm). Unique across the entire wifid binary.
 *
 * The function starts 4 bytes before this pattern.
 */
#if defined(__arm__)
static const uint8_t kRSN_IE_Pattern_ARM[] = {
    0x2D, 0xE9, 0x00, 0x0D,    /* push.w {r8, r10, r11} */
    0xA2, 0xB0,                /* sub sp, #0x88 */
    0x4F, 0xF2, 0xC3, 0x06,    /* movw r6, #0xF0C3 */
    0xCF, 0xF6, 0xFF, 0x76,    /* movt r6, #0xFFFF */
};
#define kRSN_IE_Pattern_ARM_Offset 4  /* pattern starts 4 bytes into function */
#endif

static void *findRSN_IE_Parser(void) {
    const mach_header_t *header = (const mach_header_t *)_dyld_get_image_header(0);
    if (!header) {
        syslog(LOG_ERR, TAG ": could not get main image header");
        return NULL;
    }
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);

    uintptr_t text_addr;
    size_t text_size;
    if (!findSection(header, slide, "__TEXT", "__text", &text_addr, &text_size)) {
        syslog(LOG_ERR, TAG ": __TEXT.__text section not found");
        return NULL;
    }

    const uint8_t *pattern;
    size_t pattern_len;
    size_t prologue_offset;
    size_t scan_align;

#if defined(__arm__)
    pattern = kRSN_IE_Pattern_ARM;
    pattern_len = sizeof(kRSN_IE_Pattern_ARM);
    prologue_offset = kRSN_IE_Pattern_ARM_Offset;
    scan_align = 2; /* Thumb-2 */
#elif defined(__arm64__) || defined(__aarch64__)
    syslog(LOG_ERR, TAG ": arm64 pattern not yet implemented — "
           "please provide the arm64 wifid binary for analysis");
    return NULL;
#else
    syslog(LOG_ERR, TAG ": unsupported architecture");
    return NULL;
#endif

    /* Scan __text for the pattern */
    if (text_size < pattern_len) {
        syslog(LOG_ERR, TAG ": __text section too small");
        return NULL;
    }
    const uint8_t *scan = (const uint8_t *)text_addr;
    const uint8_t *scan_end = scan + text_size - pattern_len;
    void *result = NULL;

    while (scan <= scan_end) {
        bool match = true;
        for (size_t k = 0; k < pattern_len; k++) {
            if (scan[k] != pattern[k]) { match = false; break; }
        }
        if (match) {
            uintptr_t func_addr = (uintptr_t)scan - prologue_offset;
            if (result) {
                syslog(LOG_ERR, TAG ": multiple pattern matches — aborting for safety");
                return NULL;
            }
            syslog(LOG_NOTICE, TAG ": found RSN IE parser at 0x%lx (pattern match at 0x%lx)",
                   (unsigned long)func_addr, (unsigned long)scan);
            /* Set Thumb bit for ARM32 */
            func_addr |= 1;
            result = (void *)func_addr;
        }
        scan += scan_align;
    }

    if (!result)
        syslog(LOG_ERR, TAG ": RSN IE parser pattern not found in __text");
    return result;
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
