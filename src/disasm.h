/*
 * disasm.h — Architecture-specific instruction decoders for finding
 *            code references to known addresses in __text.
 *
 * Provides two functions with identical signatures on both architectures:
 *   findCodeRef()  — find code that materializes a given address
 *   findFuncStart() — walk backwards to find the function prologue
 *
 * Also provides FUNC_PTR() to convert a raw address to a callable pointer.
 */

#ifndef DISASM_H
#define DISASM_H

#include "macho.h"

#if defined(__arm__)
/* ── Thumb-2 ──
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

/*
 * Scan for movw/movt/add-pc sequences that compute `target`.
 * The compiler may interleave unrelated instructions between them
 * (observed on iOS 9.3.6), so we search a small window for each step.
 * If `after` is non-zero, only return results at addresses > after.
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
/* ── AArch64 ──
 *
 * Pattern: adrp Xd, #page; add Xd, Xd, #offset
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
        /* stp x29, x30, [sp, #imm]! (pre-index, function prologue)
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

#endif /* DISASM_H */
