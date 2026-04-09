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
#include <mach-o/loader.h>
#include <syslog.h>
#include <stdint.h>

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

/* ── Mach-O helpers ── */

#ifdef __LP64__
typedef struct mach_header_64      mach_header_t;
typedef struct section_64          section_t;
typedef struct segment_command_64  segment_command_t;
#define LC_SEGMENT_T  LC_SEGMENT_64
#define CFSTR_STRIDE  32
#define CFSTR_STR_OFF 16
#else
typedef struct mach_header         mach_header_t;
typedef struct section             section_t;
typedef struct segment_command     segment_command_t;
#define LC_SEGMENT_T  LC_SEGMENT
#define CFSTR_STRIDE  16
#define CFSTR_STR_OFF 8
#endif

typedef struct { uintptr_t addr; size_t size; } region_t;

static inline bool streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static bool findSection(const mach_header_t *header, intptr_t slide,
                        const char *segname, const char *sectname,
                        region_t *out) {
    uintptr_t cursor = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_T) {
            segment_command_t *seg = (segment_command_t *)cursor;
            if (streq(seg->segname, segname)) {
                section_t *sect = (section_t *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (streq(sect[j].sectname, sectname)) {
                        out->addr = sect[j].addr + slide;
                        out->size = sect[j].size;
                        return true;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return false;
}

/* Find a NUL-terminated C string in a region */
static uintptr_t findCString(region_t *r, const char *target) {
    size_t len = 0;
    for (const char *p = target; *p; p++) len++;
    len++; /* include NUL */
    if (len > r->size) return 0;
    const uint8_t *hay = (const uint8_t *)r->addr;
    const uint8_t *end = hay + r->size - len;
    const uint8_t *needle = (const uint8_t *)target;
    for (const uint8_t *p = hay; p <= end; p++) {
        bool match = true;
        for (size_t k = 0; k < len; k++) {
            if (p[k] != needle[k]) { match = false; break; }
        }
        if (match) return (uintptr_t)p;
    }
    return 0;
}

/* Find CFString whose c_str pointer matches cstr_addr */
static uintptr_t findCFStr(region_t *cfstr_sect, uintptr_t cstr_addr) {
    uintptr_t p   = cfstr_sect->addr;
    uintptr_t end = p + cfstr_sect->size;
    for (; p + CFSTR_STRIDE <= end; p += CFSTR_STRIDE) {
        if (*(uintptr_t *)(p + CFSTR_STR_OFF) == cstr_addr)
            return p;
    }
    return 0;
}

/* Resolve a C string name to its CFString constant address */
static uintptr_t resolveCFString(region_t *cstring, region_t *cfstr,
                                  const char *name) {
    uintptr_t cstr = findCString(cstring, name);
    return cstr ? findCFStr(cfstr, cstr) : 0;
}

/* ── Architecture-specific instruction decoders ── */

/*
 * Find code that computes a given address via instruction sequences.
 * Returns the address of the first instruction of the sequence, or 0.
 * If `after` is non-zero, only return results at addresses > after.
 */

#if defined(__arm__)
/*
 * Thumb-2 pattern: movw Rd, #lo; movt Rd, #hi; add Rd, pc
 *
 * movw T3: hw1 = 11110 i 10 0100 imm4, hw2 = 0 imm3 Rd imm8
 *   detect: (hw1 & 0xFBF0) == 0xF240
 * movt T1: hw1 = 11110 i 10 1100 imm4, hw2 = 0 imm3 Rd imm8
 *   detect: (hw1 & 0xFBF0) == 0xF2C0
 * add Rd, pc: (insn16 & 0xFF78) == 0x4478
 */

static inline uint16_t rd16(const uint8_t *p) { return p[0] | (p[1] << 8); }

static inline bool isMovW(uint16_t hw1) { return (hw1 & 0xFBF0) == 0xF240; }
static inline bool isMovT(uint16_t hw1) { return (hw1 & 0xFBF0) == 0xF2C0; }

static inline uint8_t movwtReg(uint16_t hw2) { return (hw2 >> 8) & 0xF; }

static inline uint16_t movwtImm(uint16_t hw1, uint16_t hw2) {
    uint16_t imm4 = hw1 & 0xF;
    uint16_t i    = (hw1 >> 10) & 1;
    uint16_t imm3 = (hw2 >> 12) & 7;
    uint16_t imm8 = hw2 & 0xFF;
    return (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;
}

static inline bool isAddPC(uint16_t insn) { return (insn & 0xFF78) == 0x4478; }
static inline uint8_t addPCReg(uint16_t insn) { return ((insn >> 4) & 8) | (insn & 7); }

/*
 * Scan for movw/movt/add-pc sequences that compute `target`.
 * The compiler may interleave unrelated instructions between them
 * (observed on iOS 9.3.6), so we search a small window for each step.
 */
#define THUMB2_SCAN_WINDOW 16 /* bytes to search for next instruction */

static uintptr_t findCodeRef(region_t *text, uintptr_t target, uintptr_t after) {
    const uint8_t *base = (const uint8_t *)text->addr;
    const uint8_t *end  = base + text->size;
    for (const uint8_t *p = base; p + 10 <= end; p += 2) {
        if ((uintptr_t)p <= after) continue;
        uint16_t hw1 = rd16(p);
        if (!isMovW(hw1)) continue;
        uint16_t hw2 = rd16(p + 2);
        uint8_t rd = movwtReg(hw2);
        uint16_t lo = movwtImm(hw1, hw2);

        /* Search forward for movt to same register */
        const uint8_t *lim = p + 4 + THUMB2_SCAN_WINDOW;
        if (lim > end - 4) lim = end - 4;
        const uint8_t *movt_end = NULL;
        uint16_t hi = 0;
        for (const uint8_t *q = p + 4; q <= lim; q += 2) {
            uint16_t t1 = rd16(q);
            if (isMovT(t1) && movwtReg(rd16(q + 2)) == rd) {
                hi = movwtImm(t1, rd16(q + 2));
                movt_end = q + 4;
                break;
            }
        }
        if (!movt_end) continue;

        /* Search forward for add Rd, pc */
        lim = movt_end + THUMB2_SCAN_WINDOW;
        if (lim > end - 2) lim = end - 2;
        for (const uint8_t *r = movt_end; r <= lim; r += 2) {
            uint16_t insn = rd16(r);
            if (isAddPC(insn) && addPCReg(insn) == rd) {
                uint32_t imm32 = ((uint32_t)hi << 16) | lo;
                uintptr_t effective = imm32 + (uintptr_t)r + 4; /* Thumb PC = insn + 4 */
                if (effective == target) return (uintptr_t)p;
                break;
            }
        }
    }
    return 0;
}

static uintptr_t findFuncStart(uintptr_t ref, uintptr_t text_start) {
    /* Walk backwards looking for push {.., lr} prologue */
    uintptr_t cur = ref & ~(uintptr_t)1;
    uintptr_t limit = (cur > text_start + 0x4000) ? cur - 0x4000 : text_start;
    while (cur >= limit) {
        uint16_t insn = rd16((const uint8_t *)cur);
        /* push {r4+, lr}: 0xB5xx with bit 8 (LR) set */
        if ((insn & 0xFF00) == 0xB500 && (insn & 0x10))
            return cur;
        /* push.w with LR bit set */
        if (insn == 0xE92D) {
            uint16_t hw2 = rd16((const uint8_t *)(cur + 2));
            if (hw2 & 0x4000) return cur;
        }
        cur -= 2;
    }
    return 0;
}

#define FUNC_PTR(addr) ((void *)((addr) | 1)) /* set Thumb bit */

#elif defined(__arm64__) || defined(__aarch64__)
/*
 * AArch64 pattern: adrp Xd, #page; add Xd, Xd, #offset
 *
 * adrp: (insn & 0x9F000000) == 0x90000000
 * add:  (insn & 0xFFC00000) == 0x91000000 (64-bit, shift=0)
 */

static inline uint32_t rd32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline bool isADRP(uint32_t insn) { return (insn & 0x9F000000) == 0x90000000; }
static inline bool isADD64(uint32_t insn) { return (insn & 0xFFC00000) == 0x91000000; }

static inline uint8_t regD(uint32_t insn) { return insn & 0x1F; }
static inline uint8_t regN(uint32_t insn) { return (insn >> 5) & 0x1F; }

static inline int64_t adrpImm(uint32_t insn) {
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    uint32_t immlo = (insn >> 29) & 3;
    int64_t imm = (int64_t)((immhi << 2) | immlo);
    /* Sign-extend from 21 bits */
    if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
    return imm << 12;
}

static inline uint32_t addImm12(uint32_t insn) { return (insn >> 10) & 0xFFF; }

static uintptr_t findCodeRef(region_t *text, uintptr_t target, uintptr_t after) {
    const uint8_t *p   = (const uint8_t *)text->addr;
    const uint8_t *end = p + text->size - 8; /* need 2 x 4-byte instructions */
    for (; p <= end; p += 4) {
        if ((uintptr_t)p <= after) continue;
        uint32_t insn1 = rd32(p);
        if (!isADRP(insn1)) continue;
        uint32_t insn2 = rd32(p + 4);
        if (!isADD64(insn2)) continue;
        if (regD(insn1) != regN(insn2)) continue;
        uintptr_t page = (uintptr_t)p & ~(uintptr_t)0xFFF;
        uintptr_t effective = page + adrpImm(insn1) + addImm12(insn2);
        if (effective == target) return (uintptr_t)p;
    }
    return 0;
}

static uintptr_t findFuncStart(uintptr_t ref, uintptr_t text_start) {
    uintptr_t cur = ref;
    uintptr_t limit = (cur > text_start + 0x10000) ? cur - 0x10000 : text_start;
    while (cur >= limit) {
        uint32_t insn = rd32((const uint8_t *)cur);
        /* stp x29, x30, [sp, #imm]! (pre-index, sign of function prologue)
           mask 0xFFC07FFF zeros imm7 bits [21:15] */
        if ((insn & 0xFFC07FFF) == 0xA9807BFD) return cur;
        /* sub sp, sp, #N (alternate prologue start) */
        if ((insn & 0xFFC003FF) == 0xD10003FF) return cur;
        cur -= 4;
    }
    return 0;
}

#define FUNC_PTR(addr) ((void *)(addr))

#else
#error "Unsupported architecture"
#endif

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
