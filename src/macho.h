/*
 * macho.h -- Mach-O section lookup and CFString resolution helpers
 */

#ifndef MACHO_H
#define MACHO_H

#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>

/* -- Arch-dependent Mach-O types -- */

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

/* Address + size pair describing a loaded section */
typedef struct { uintptr_t addr; size_t size; } region_t;

/* -- Inline string helpers --
 * iOS 10.3 SDK TBDs don't export strcmp; an inline reimplementation
 * sidesteps the missing symbol and lets the compiler constant-fold
 * comparisons against string literals.  __builtin_strcmp would work
 * on recent clang but can still emit a libc call under -O0 / PGO,
 * so the hand-rolled version is used for safety. */

static inline bool streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

/* -- Section lookup -- */

static bool findSection(const mach_header_t *header, intptr_t slide,
                        const char *segname, const char *sectname,
                        region_t *out) {
    uintptr_t cursor = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cursor;
        /* Guard against malformed headers: a zero cmdsize would spin
         * forever.  dyld-loaded Apple binaries are well-formed, but
         * cost of the check is one compare. */
        if (lc->cmdsize < sizeof(struct load_command)) break;
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

/* -- String / CFString resolution -- */

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

/* Find CFString whose c_str pointer matches cstr_addr.
 * The __cfstring section is laid out as an array of CFConstStringClassReference
 * structs (CFSTR_STRIDE bytes each, naturally aligned at section start), so
 * the c_str pointer at offset CFSTR_STR_OFF is always pointer-aligned.  The
 * cast below relies on that alignment guarantee. */
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

#endif /* MACHO_H */
