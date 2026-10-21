#ifndef LOADER_STAGING_1160_H
#define LOADER_STAGING_1160_H

#include "linux.h"
#include <stddef.h>

/*
 * Publish the already-populated Linux input mappings in the PID-1 pmap using
 * the checked Stage-1A/1B transaction that passed on retail firmware 11.60.
 *
 * On success this function takes ownership of both mappings and deliberately
 * keeps their live mappings, the linux_info backing page, and every new page
 * table alive for the rest/wake handoff.  On an ordinary failure it restores
 * every journaled page-table write and leaves ownership with the caller.  A
 * rollback verification failure is contained by holding until a cold reboot.
 */
int stage_linux_aliases_1160(const struct linux_info *info, void *bzimage,
                             size_t bzimage_mapping_size, void *initrd,
                             size_t initrd_mapping_size);

#endif
