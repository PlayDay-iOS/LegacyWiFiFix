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

/* ── Mach-O helpers ── */

#ifdef __LP64__
typedef struct mach_header_64      mach_header_t;
typedef struct section_64          section_t;
typedef struct segment_command_64  segment_command_t;
#define LC_SEGMENT_T  LC_SEGMENT_64
#define CFSTR_STRIDE  32
#define CFSTR_STR_OFF 16
#define PTR_SIZE      8
#else
typedef struct mach_header         mach_header_t;
typedef struct section             section_t;
typedef struct segment_command     segment_command_t;
#define LC_SEGMENT_T  LC_SEGMENT
#define CFSTR_STRIDE  16
#define CFSTR_STR_OFF 8
#define PTR_SIZE      4
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
    uintptr_t cur = cfstr_sect->addr;
    uintptr_t end = cur + cfstr_sect->size;
    while (cur + CFSTR_STRIDE <= end) {
        uintptr_t ptr = 0;
        for (int i = 0; i < PTR_SIZE; i++)
            ptr |= (uintptr_t)((uint8_t *)(cur + CFSTR_STR_OFF))[i] << (i * 8);
        if (ptr == cstr_addr) return cur;
        cur += CFSTR_STRIDE;
    }
    return 0;
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

static uintptr_t findCodeRef(region_t *text, uintptr_t target, uintptr_t after) {
    const uint8_t *p   = (const uint8_t *)text->addr;
    const uint8_t *end = p + text->size - 10; /* need at least 10 bytes: 4+4+2 */
    for (; p <= end; p += 2) {
        if ((uintptr_t)p <= after) continue;
        uint16_t hw1a = rd16(p);
        if (!isMovW(hw1a)) continue;
        uint16_t hw2a = rd16(p + 2);
        uint8_t rd = movwtReg(hw2a);
        uint16_t hw1b = rd16(p + 4);
        if (!isMovT(hw1b)) continue;
        uint16_t hw2b = rd16(p + 6);
        if (movwtReg(hw2b) != rd) continue;
        uint16_t add_insn = rd16(p + 8);
        if (!isAddPC(add_insn) || addPCReg(add_insn) != rd) continue;
        /* Compute effective address: PC at add instruction = addr + 8 + 4 */
        uint32_t imm32 = (movwtImm(hw1b, hw2b) << 16) | movwtImm(hw1a, hw2a);
        uintptr_t add_pc = (uintptr_t)(p + 8) + 4; /* Thumb PC = insn + 4 */
        uintptr_t effective = imm32 + add_pc;
        if (effective == target) return (uintptr_t)p;
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
        /* stp x29, x30, [sp, #-N]!  (sign of function prologue) */
        if ((insn & 0xFFE07FFF) == 0xA9807BFD) return cur;
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

    /* Locate both CFString constants we need */
    uintptr_t ver_cstr = findCString(&cstring, "IE_KEY_RSN_VERSION");
    uintptr_t auth_cstr = findCString(&cstring, "IE_KEY_RSN_AUTHSELS");
    if (!ver_cstr || !auth_cstr) {
        syslog(LOG_ERR, TAG ": RSN IE key strings not found in __cstring");
        return NULL;
    }
    uintptr_t ver_cf = findCFStr(&cfstring, ver_cstr);
    uintptr_t auth_cf = findCFStr(&cfstring, auth_cstr);
    if (!ver_cf || !auth_cf) {
        syslog(LOG_ERR, TAG ": CFString wrappers not found in __cfstring");
        return NULL;
    }

    syslog(LOG_NOTICE, TAG ": VERSION cfstr=0x%lx  AUTHSELS cfstr=0x%lx",
           (unsigned long)ver_cf, (unsigned long)auth_cf);

    /* Find code references to VERSION CFString, then verify:
       1. AUTHSELS is also referenced within the same function
       2. VERSION appears early (within ~512 bytes of func start) — this
          distinguishes the RSN IE parser from _performAssociation, which
          also references both strings but much deeper into the function. */
    uintptr_t ref = 0;
    while ((ref = findCodeRef(&text, ver_cf, ref)) != 0) {
        uintptr_t func = findFuncStart(ref, text.addr);
        if (!func) continue;

        /* VERSION must be near the function start (parser: ~0xBE, assoc: ~0x8E2) */
        if (ref - func > 0x200) continue;

        /* AUTHSELS must also be referenced within the function (~1.3KB) */
        region_t func_region = { .addr = func, .size = 0x800 };
        if (findCodeRef(&func_region, auth_cf, 0)) {
            syslog(LOG_NOTICE, TAG ": found RSN IE parser at 0x%lx "
                   "(VERSION ref at 0x%lx, offset +0x%lx, verified AUTHSELS)",
                   (unsigned long)func, (unsigned long)ref,
                   (unsigned long)(ref - func));
            return FUNC_PTR(func);
        }
    }

    syslog(LOG_ERR, TAG ": no function references both VERSION and AUTHSELS");
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
