/*
 * test_finder.c -- Host-side test for the RSN IE parser finder.
 *
 * Compile (32-bit targets -- armv6/armv7):
 *   gcc -m32 -I test/compat -I src \
 *       -D__arm__ -D__ARM_ARCH=6 \
 *       -DTEST -o test_armv6 test/test_finder.c
 *
 *   gcc -m32 -I test/compat -I src \
 *       -D__arm__ -D'__ARM_ARCH=7' \
 *       -DTEST -o test_armv7 test/test_finder.c
 *
 * Compile (64-bit target -- arm64):
 *   gcc -I test/compat -I src \
 *       -D__arm64__ -D__LP64__ \
 *       -DTEST -o test_arm64 test/test_finder.c
 *
 * Run:
 *   ./test_armv6 /path/to/WiFiManager 0x00023ed4
 *   ./test_armv7 /path/to/wifid        0x000c417e
 *   ./test_arm64 /path/to/wifid        0x1000dbdf8
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

/* Stub out syslog -- just print to stderr in test mode */
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
static void syslog(int priority, const char *fmt, ...) {
    (void)priority;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#include "macho.h"
#include "disasm.h"
#include "finder.h"

/*
 * Simulate dyld rebasing: walk __DATA.__cfstring and add slide to each
 * string pointer.  Without this, the unrelocated virtual addresses in the
 * CFString structs won't match the host-address C strings found by
 * findCString().
 */
static void rebaseCFStrings(const mach_header_t *header, intptr_t slide) {
    region_t cfstr;
    if (!findSection(header, slide, "__DATA", "__cfstring", &cfstr))
        return;
    uint8_t *p   = (uint8_t *)cfstr.addr;
    uint8_t *end = p + cfstr.size;
    for (; p + CFSTR_STRIDE <= end; p += CFSTR_STRIDE) {
#ifdef __LP64__
        *(uint64_t *)(p + CFSTR_STR_OFF) += slide;
#else
        *(uint32_t *)(p + CFSTR_STR_OFF) += (uint32_t)slide;
#endif
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <macho-binary> <expected-vaddr-hex>\n", argv[0]);
        return 2;
    }

    const char *path = argv[1];
    uintptr_t expected_vaddr = (uintptr_t)strtoull(argv[2], NULL, 16);

    /* mmap the binary */
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 2; }

    struct stat st;
    fstat(fd, &st);

    void *map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { perror("mmap"); return 2; }

    const mach_header_t *header = (const mach_header_t *)map;

    /* Compute slide using the __TEXT segment's vmaddr.  Executables have
     * __PAGEZERO as the first segment (vmaddr=0), so we must specifically
     * find __TEXT to get the correct base for the slide calculation. */
    uintptr_t text_vmaddr = 0;
    uintptr_t cursor = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_T) {
            segment_command_t *seg = (segment_command_t *)cursor;
            if (streq(seg->segname, "__TEXT")) {
                text_vmaddr = seg->vmaddr;
                break;
            }
        }
        cursor += lc->cmdsize;
    }
    intptr_t slide = (uintptr_t)map - text_vmaddr;

    /* Simulate dyld pointer rebasing */
    rebaseCFStrings(header, slide);

    /* Run the finder */
    uintptr_t found = findRSN_IE_ParserInImage(header, slide);

    /* Convert found host address back to virtual address for comparison */
    uintptr_t found_vaddr = found ? found - slide : 0;

    munmap(map, st.st_size);

    if (found_vaddr == expected_vaddr) {
        printf("PASS  %s  found=0x%lx\n", path, (unsigned long)found_vaddr);
        return 0;
    } else {
        printf("FAIL  %s  expected=0x%lx  found=0x%lx\n",
               path, (unsigned long)expected_vaddr, (unsigned long)found_vaddr);
        return 1;
    }
}
