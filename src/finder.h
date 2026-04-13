/*
 * finder.h — Locate the RSN IE parser function in a Mach-O image.
 *
 * Returns the raw function start address (without FUNC_PTR conversion),
 * or 0 if not found.  Shared by the tweak and the test harness.
 */

#ifndef FINDER_H
#define FINDER_H

#include "disasm.h"   /* includes macho.h */
#include <syslog.h>

#ifndef TAG
#define TAG "WiFiFixOldiOS"
#endif

/* Heuristic thresholds — validated against wifid/WiFiManager from
 * iOS 3.1.3, 4.2.1, 4.3.5, 5.1.1, 6.1.6, 7.1.2, 8.4.1, 9.3.6, 10.3.3,
 * 10.3.4, 11.4.1 and 12.5.8.
 * VERSION_MAX_OFFSET: The RSN IE parser references IE_KEY_RSN_VERSION early
 * (observed: +0xC6 .. +0x108), while _performAssociation references it much
 * later (+0x402 .. +0x4CC).  A 0x200 cutoff cleanly separates them.
 * FUNC_BODY_RANGE: Maximum range from function start to scan for secondary
 * string references (AUTHSELS observed at +0x2DE .. +0x3CC). */
#define VERSION_MAX_OFFSET  0x200
#define FUNC_BODY_RANGE     0x800

static uintptr_t findRSN_IE_ParserInImage(const mach_header_t *header,
                                           intptr_t slide) {
    region_t text, cstring, cfstring;
    if (!findSection(header, slide, "__TEXT", "__text",     &text)    ||
        !findSection(header, slide, "__TEXT", "__cstring",  &cstring) ||
        !findSection(header, slide, "__DATA", "__cfstring", &cfstring)) {
        syslog(LOG_ERR, TAG ": required Mach-O sections not found");
        return 0;
    }

    uintptr_t ver_cf  = resolveCFString(&cstring, &cfstring, "IE_KEY_RSN_VERSION");
    uintptr_t auth_cf = resolveCFString(&cstring, &cfstring, "IE_KEY_RSN_AUTHSELS");
    if (!ver_cf || !auth_cf) {
        syslog(LOG_ERR, TAG ": RSN IE key CFStrings not found");
        return 0;
    }

    syslog(LOG_NOTICE, TAG ": VERSION cfstr=%p  AUTHSELS cfstr=%p",
           (void *)ver_cf, (void *)auth_cf);

    uintptr_t ref = 0;
    while ((ref = findCodeRef(&text, ver_cf, ref)) != 0) {
        uintptr_t func = findFuncStart(ref, text.addr);
        if (!func) {
            syslog(LOG_NOTICE, TAG ": skip ref=%p (no prologue found)",
                   (void *)ref);
            continue;
        }
        if (ref - func > VERSION_MAX_OFFSET) {
            syslog(LOG_NOTICE, TAG ": skip ref=%p func=%p (VERSION +0x%lx > 0x%x)",
                   (void *)ref, (void *)func,
                   (unsigned long)(ref - func), VERSION_MAX_OFFSET);
            continue;
        }

        size_t bodySize = FUNC_BODY_RANGE;
        if (func + bodySize > text.addr + text.size)
            bodySize = text.addr + text.size - func;
        region_t body = { func, bodySize };
        if (!findCodeRef(&body, auth_cf, 0)) {
            syslog(LOG_NOTICE, TAG ": skip func=%p (AUTHSELS not in body, +0x%lx scan)",
                   (void *)func, (unsigned long)bodySize);
            continue;
        }

        syslog(LOG_NOTICE, TAG ": found parseRSN_IE at %p (VERSION +0x%lx)",
               (void *)func, (unsigned long)(ref - func));
        return func;
    }

    syslog(LOG_ERR, TAG ": could not locate parseRSN_IE");
    return 0;
}

#endif /* FINDER_H */
