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

#if PS5_1160_BOUNDED_BOOT_FILES
#include <stdint.h>
/* Nonzero when the 16-KiB page at pa overlaps the range the wake blob copies
 * Linux into.  Valid after stage_linux_aliases_1160 has started. */
int pa_in_wake_copy_1160(uint64_t pa);

/* stage_linux_aliases_1160 returns this instead of -1 when it refused a page
 * table or the code cave inside the copy range.  Those stay where they are
 * until a reboot, so running the loader again in the same boot cannot help. */
#define STAGING_REBOOT_FIRST_1160 (-2)

/* The #SX stack page that staging took and checked before writing anything,
 * or 0 if it did not. */
uint64_t sx_stack_page_1160(void);

/* Nonzero when the 16-KiB page at pa overlaps the page under the #SX stack
 * page, which the wake blob's stack reaches past 0x1040 bytes. */
int pa_under_sx_stack_1160(uint64_t pa);
#endif

#endif
