/*
 * disasm.h -- Architecture-specific instruction decoders for finding
 *            code references to known addresses in __text.
 *
 * Provides two functions with identical signatures on both architectures:
 *   findCodeRef()  -- find code that materializes a given address
 *   findFuncStart() -- walk backwards to find the function prologue
 *
 * Also provides FUNC_PTR() to convert a raw address to a callable pointer.
 */

#ifndef DISASM_H
#define DISASM_H

#include "macho.h"

#if defined(__arm__) && __ARM_ARCH >= 7
/* -- Thumb-2 / Thumb-16 (armv7) --
 *
 * Pattern: movw Rd, #lo; [interleaved insns]; movt Rd, #hi; [...]; add Rd, pc
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

/* Thumb-16 ldr Rt, [pc, #imm8*4]: (hw & 0xF800) == 0x4800 */
static inline bool isLdrLiteral16(uint16_t hw) { return (hw & 0xF800) == 0x4800; }
static inline uint8_t ldrLitReg(uint16_t hw) { return (hw >> 8) & 7; }
static inline uint32_t ldrLitOff(uint16_t hw) { return (hw & 0xFF) << 2; }

/*
 * Scan for instruction sequences that compute `target`.
 * Recognizes two patterns:
 *   1. movw Rd, #lo; movt Rd, #hi; add Rd, pc  (Thumb-2, iOS 6+)
 *   2. ldr  Rt, [pc, #off]; add Rd, pc          (Thumb-16, iOS 4.x)
 * If `after` is non-zero, only return results at addresses > after.
 */
#define THUMB2_SCAN_WINDOW  16 /* bytes to search for next instruction */
#define THUMB16_SCAN_WINDOW 16 /* same window, used by ldr-literal pattern */

static uintptr_t findCodeRef(region_t *text, uintptr_t target, uintptr_t after) {
    const uint8_t *base = (const uint8_t *)text->addr;
    const uint8_t *end  = base + text->size;
    for (const uint8_t *p = base; p + 4 <= end; p += 2) {
        if ((uintptr_t)p <= after) continue;
        uint16_t hw1 = rd16(p);

        /* -- Pattern 1: movw / movt / add-pc (Thumb-2) -- */
        if (isMovW(hw1) && p + 10 <= end) {
            uint16_t hw2 = rd16(p + 2);
            uint8_t rd = movwtReg(hw2);
            uint16_t lo = movwtImm(hw1, hw2);

            const uint8_t *lim = p + 4 + THUMB2_SCAN_WINDOW;
            if (lim + 4 > end) lim = end - 4;
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
            if (movt_end) {
                lim = movt_end + THUMB2_SCAN_WINDOW;
                if (lim + 2 > end) lim = end - 2;
                for (const uint8_t *r = movt_end; r <= lim; r += 2) {
                    uint16_t insn = rd16(r);
                    if (isAddPC(insn) && addPCReg(insn) == rd) {
                        uint32_t imm32 = ((uint32_t)hi << 16) | lo;
                        uintptr_t effective = imm32 + (uintptr_t)r + 4;
                        if (effective == target) return (uintptr_t)p;
                        break;
                    }
                }
            }
        }

        /* -- Pattern 2: ldr Rt, [pc, #imm8*4] / add Rd, pc (Thumb-16) -- */
        if (isLdrLiteral16(hw1)) {
            uint8_t rt = ldrLitReg(hw1);
            uint32_t off = ldrLitOff(hw1);
            uintptr_t pc_ldr = ((uintptr_t)p + 4) & ~(uintptr_t)3; /* Align(PC,4) */
            uintptr_t pool_addr = pc_ldr + off;
            if (pool_addr + 4 > (uintptr_t)end) continue;
            uint32_t pool_val = *(uint32_t *)pool_addr;

            const uint8_t *lim = p + 2 + THUMB16_SCAN_WINDOW;
            if (lim + 2 > end) lim = end - 2;
            for (const uint8_t *r = p + 2; r <= lim; r += 2) {
                uint16_t insn = rd16(r);
                if (isAddPC(insn) && addPCReg(insn) == rt) {
                    uintptr_t effective = pool_val + (uintptr_t)r + 4;
                    if (effective == target) return (uintptr_t)p;
                    break;
                }
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
        /* push {..., lr} with R4 in the register list: opcode 0xB5xx
         * implies bit 8 (LR) is set; bit 4 of reglist requires R4.
         * ARM AAPCS callee-saved prologues always save R4 first, so this
         * reliably identifies function starts in compiler-emitted code. */
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

#elif defined(__arm__)
/* -- ARM mode (armv6) --
 *
 * Pattern: ldr Rd, [pc, #imm12]; [...]; add Rd, pc, Rd
 *
 * The ldr loads a PC-relative offset from a literal pool at the end of the
 * function.  The add then computes the absolute address.
 *
 * ldr Rd, [pc, #imm12]:  (insn & 0x0F7F0000) == 0x051F0000
 *   U-bit (bit 23): 1 = add, 0 = subtract
 *   Rd: bits [15:12]
 *   imm12: bits [11:0]
 *
 * add Rd, pc, Rm (unshifted): (insn & 0x0FEF0FF0) == 0x008F0000
 *   Rd: bits [15:12], Rm: bits [3:0]
 */

static inline uint32_t rd32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline bool isLdrPCImm(uint32_t insn) {
    return (insn & 0x0F7F0000) == 0x051F0000;
}
static inline uint8_t ldrPCRd(uint32_t insn) { return (insn >> 12) & 0xF; }
static inline int32_t ldrPCOff(uint32_t insn) {
    int32_t off = insn & 0xFFF;
    if (!(insn & (1 << 23))) off = -off; /* U bit */
    return off;
}

static inline bool isAddPCReg(uint32_t insn) {
    return (insn & 0x0FEF0FF0) == 0x008F0000;
}
static inline uint8_t addPCRd(uint32_t insn) { return (insn >> 12) & 0xF; }
static inline uint8_t addPCRm(uint32_t insn) { return insn & 0xF; }

#define ARM_SCAN_WINDOW 16 /* bytes (4 instructions) */

static uintptr_t findCodeRef(region_t *text, uintptr_t target, uintptr_t after) {
    const uint8_t *base = (const uint8_t *)text->addr;
    const uint8_t *end  = base + text->size;
    for (const uint8_t *p = base; p + 8 <= end; p += 4) {
        if ((uintptr_t)p <= after) continue;
        uint32_t insn = rd32(p);
        if (!isLdrPCImm(insn)) continue;

        uint8_t rd = ldrPCRd(insn);
        int32_t off = ldrPCOff(insn);
        uintptr_t pool_addr = (uintptr_t)p + 8 + off;   /* ARM PC = insn + 8 */
        if (pool_addr < (uintptr_t)base || pool_addr + 4 > (uintptr_t)end)
            continue;
        uint32_t pool_val = rd32((const uint8_t *)pool_addr);

        /* Search forward for add Rd, pc, Rd */
        const uint8_t *lim = p + 4 + ARM_SCAN_WINDOW;
        if (lim + 4 > end) lim = end - 4;
        for (const uint8_t *q = p + 4; q <= lim; q += 4) {
            uint32_t a = rd32(q);
            if (isAddPCReg(a) && addPCRd(a) == rd && addPCRm(a) == rd) {
                uintptr_t effective = pool_val + (uintptr_t)q + 8; /* ARM PC = insn + 8 */
                if (effective == target) return (uintptr_t)p;
                break;
            }
        }
    }
    return 0;
}

static uintptr_t findFuncStart(uintptr_t ref, uintptr_t text_start) {
    /* Walk backwards looking for stmdb sp!, {.., lr} prologue.
     * ARM encoding: (insn & 0x0FFF0000) == 0x092D0000 with LR bit set. */
    uintptr_t cur = ref & ~(uintptr_t)3;
    uintptr_t limit = (cur > text_start + 0x4000) ? cur - 0x4000 : text_start;
    while (cur >= limit) {
        uint32_t insn = rd32((const uint8_t *)cur);
        if ((insn & 0x0FFF0000) == 0x092D0000 && (insn & 0x4000))
            return cur;
        cur -= 4;
    }
    return 0;
}

#define FUNC_PTR(addr) ((void *)(addr)) /* ARM mode: no Thumb bit */

#elif defined(__arm64__) || defined(__aarch64__)
/* -- AArch64 --
 *
 * Two patterns are recognized:
 *   1. adrp Xd, #page; add Xd, Xd, #offset
 *   2. adr  Xd, label                   (linker-relaxed from adrp+add when
 *                                        the target is within +/-1 MiB)
 *
 * adrp: (insn & 0x9F000000) == 0x90000000  (bit 31 = 1)
 * adr:  (insn & 0x9F000000) == 0x10000000  (bit 31 = 0)
 * add:  (insn & 0xFFC00000) == 0x91000000 (64-bit, shift=0)
 */

static inline uint32_t rd32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline bool isADRP(uint32_t insn) { return (insn & 0x9F000000) == 0x90000000; }
static inline bool isADR(uint32_t insn)  { return (insn & 0x9F000000) == 0x10000000; }
static inline bool isADD64(uint32_t insn) { return (insn & 0xFFC00000) == 0x91000000; }

static inline uint8_t regD(uint32_t insn) { return insn & 0x1F; }
static inline uint8_t regN(uint32_t insn) { return (insn >> 5) & 0x1F; }

/* Shared immediate decoder for adr/adrp: 21-bit signed immediate split into
 * immlo (bits [30:29]) and immhi (bits [23:5]).  For adrp, the caller shifts
 * left by 12 to get the page offset; for adr, the value is used directly. */
static inline int64_t adrImm21(uint32_t insn) {
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    uint32_t immlo = (insn >> 29) & 3;
    int64_t imm = (int64_t)((immhi << 2) | immlo);
    if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
    return imm;
}
static inline int64_t adrpImm(uint32_t insn) { return adrImm21(insn) << 12; }
static inline int64_t adrImm(uint32_t insn)  { return adrImm21(insn); }

static inline uint32_t addImm12(uint32_t insn) { return (insn >> 10) & 0xFFF; }

/* Scan window: compiler may insert instructions between adrp and add */
#define AARCH64_SCAN_WINDOW 12 /* bytes (3 instructions) */

static uintptr_t findCodeRef(region_t *text, uintptr_t target, uintptr_t after) {
    const uint8_t *base = (const uint8_t *)text->addr;
    const uint8_t *end  = base + text->size;
    for (const uint8_t *p = base; p + 4 <= end; p += 4) {
        if ((uintptr_t)p <= after) continue;
        uint32_t insn1 = rd32(p);

        /* -- Pattern 1: adrp + add -- */
        if (isADRP(insn1) && p + 8 <= end) {
            uint8_t rd = regD(insn1);
            uintptr_t page = (uintptr_t)p & ~(uintptr_t)0xFFF;
            int64_t pageOff = adrpImm(insn1);

            const uint8_t *lim = p + 4 + AARCH64_SCAN_WINDOW;
            if (lim + 4 > end) lim = end - 4;
            for (const uint8_t *q = p + 4; q <= lim; q += 4) {
                uint32_t insn2 = rd32(q);
                if (!isADD64(insn2)) continue;
                if (regN(insn2) != rd) continue;
                uintptr_t effective = page + pageOff + addImm12(insn2);
                if (effective == target) return (uintptr_t)p;
                break;
            }
            continue;
        }

        /* -- Pattern 2: adr (linker-relaxed adrp+add) -- */
        if (isADR(insn1)) {
            uintptr_t effective = (uintptr_t)p + (intptr_t)adrImm(insn1);
            if (effective == target) return (uintptr_t)p;
        }
    }
    return 0;
}

static uintptr_t findFuncStart(uintptr_t ref, uintptr_t text_start) {
    uintptr_t cur = ref;
    uintptr_t limit = (cur > text_start + 0x10000) ? cur - 0x10000 : text_start;
    while (cur >= limit) {
        uint32_t insn = rd32((const uint8_t *)cur);
        /* stp x29, x30, [sp, #imm]! (pre-index, function prologue)
           mask 0xFFC07FFF zeros imm7 bits [21:15] */
        if ((insn & 0xFFC07FFF) == 0xA9807BFD) return cur;
        /* sub sp, sp, #N is a prologue only if followed by stp x29, x30
           within 8 instructions (large functions save many callee-saved
           registers before saving fp/lr, e.g. stp x28, x27; stp x26, x25;
           ...; stp x29, x30 -- observed up to 6 instructions on iOS 10.3.3). */
        if ((insn & 0xFFC003FF) == 0xD10003FF) {
            for (int off = 4; off <= 32 && cur + off + 4 <= ref; off += 4) {
                uint32_t next = rd32((const uint8_t *)(cur + off));
                /* stp x29, x30, [sp, #imm] -- signed-offset form only
                 * (mask constrains bits [25:23] = 010; pre-/post-index
                 * forms are already handled by the earlier check). */
                if ((next & 0x7FC07FFF) == 0x29007BFD) return cur;
            }
        }
        cur -= 4;
    }
    return 0;
}

#define FUNC_PTR(addr) ((void *)(addr))

#else
#error "Unsupported architecture"
#endif

#endif /* DISASM_H */
