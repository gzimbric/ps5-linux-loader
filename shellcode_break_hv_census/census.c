/*
 * Read-only 11.60 VMCB census for the startup AP.  Hypervisor-derived
 * pointers remain const volatile.  The only stores are to the bounded report
 * and to the kernel carrier state that this payload is responsible for
 * restoring before it returns to the stock startup callback.
 */
#include "census_params.h"
#include <stddef.h>
#include <stdint.h>

#define FRAME 0x1000ULL
#define NCPU 16
#define TSS_STRIDE 0x68ULL
#define TSS_IST6 0x4cULL

#define VMCB_IOPM_BASE_PA 0x40
#define VMCB_MSRPM_BASE_PA 0x48
#define VMCB_ASID 0x58
#define VMCB_NESTED_CTRL 0x90
#define VMCB_NESTED_CR3 0xb0
#define VMCB_CLEAN 0xc0
#define VMCB_GUEST_CR3 0x550
#define VMCB_GUEST_RIP 0x578

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL
static uint64_t load64(const volatile void *address) {
  return *(const volatile uint64_t *)address;
}

static uint32_t load32(const volatile void *address) {
  return *(const volatile uint32_t *)address;
}

static int bitmap_test(const volatile uint8_t *bitmap, uint64_t bit,
                       uint64_t bytes) {
  if ((bit >> 3) >= bytes)
    return 0;
  return (bitmap[bit >> 3] >> (bit & 7)) & 1;
}

static int valid_region_page(uint64_t pa, uint64_t base, uint64_t size) {
  return (pa & (FRAME - 1)) == 0 && pa >= base && pa - base < size;
}

static uint64_t hash_word(uint64_t hash, uint64_t value) {
  for (int i = 0; i < 8; i++) {
    hash ^= (uint8_t)value;
    hash *= FNV_PRIME;
    value >>= 8;
  }
  return hash;
}

static uint64_t candidate_hash(const volatile uint8_t *p, uint64_t pa,
                               uint64_t hash) {
  hash = hash_word(hash, pa);
  hash = hash_word(hash, load64(p + VMCB_NESTED_CTRL));
  hash = hash_word(hash, load32(p + VMCB_CLEAN));
  return hash;
}

static int hash_mapped_range(uint64_t dmap, uint64_t base, uint64_t size,
                             const volatile uint8_t *bitmap,
                             uint64_t bitmap_bytes, uint64_t pa,
                             uint64_t length, uint64_t *hash_out) {
  if (!length || pa < base || pa - base > size || length > size - (pa - base))
    return -1;
  const uint64_t first = (pa - base) / FRAME;
  const uint64_t last = (pa - base + length - 1) / FRAME;
  if (first != last || !bitmap_test(bitmap, first, bitmap_bytes))
    return -1;

  const volatile uint8_t *p =
      (const volatile uint8_t *)(uintptr_t)(dmap + pa);
  uint64_t hash = FNV_OFFSET;
  for (uint64_t i = 0; i < length; i++) {
    hash ^= p[i];
    hash *= FNV_PRIME;
  }
  *hash_out = hash;
  return 0;
}

void census_vmcb(const uint64_t *param) {
  const uint64_t dmap = param[CENSUS_P_DMAP];
  const uint64_t base = param[CENSUS_P_HV_BASE];
  const uint64_t size = param[CENSUS_P_HV_SIZE];
  const uint64_t scan_lo = param[CENSUS_P_SCAN_LO];
  const uint64_t scan_hi = param[CENSUS_P_SCAN_HI];
  const uint64_t needle_rip = param[CENSUS_P_NEEDLE_RIP];
  const uint64_t needle_cr3 = param[CENSUS_P_NEEDLE_CR3];
  const uint64_t code_base = param[CENSUS_P_CODE_BASE];
  const volatile uint8_t *bitmap =
      (const volatile uint8_t *)(uintptr_t)param[CENSUS_P_BITMAP];
  const uint64_t bitmap_bytes = param[CENSUS_P_BITMAP_BYTES];
  volatile struct census_report *report =
      (volatile struct census_report *)(uintptr_t)param[CENSUS_P_REPORT];
  const volatile uint64_t *saved =
      (const volatile uint64_t *)(uintptr_t)param[CENSUS_P_SAVED_ISTS];
  volatile uint64_t *carrier_state =
      (volatile uint64_t *)(uintptr_t)param[CENSUS_P_CARRIER_STATE];
  const uint64_t tss_base = param[CENSUS_P_TSS_BASE];
  uint64_t self_pa = 0, self_count = 0, self_nctl = 0, self_ncr3 = 0;
  uint64_t self_asid = 0, self_iopm = 0, self_msrpm = 0;
  uint64_t mapped = 0, scanned = 0, targets = 0, recorded = 0;
  uint64_t before = FNV_OFFSET, after = FNV_OFFSET, error = 0, anchor_hash;

  report->magic = CENSUS_REPORT_MAGIC;
  report->version = CENSUS_REPORT_VERSION;
  report->size = sizeof(*report);
  report->state = CENSUS_STATE_ENTERED;
  report->hv_base = base;
  report->hv_size = size;
  report->scan_lo = scan_lo;
  report->scan_hi = scan_hi;
  report->code_base = code_base;
  report->boundary_hash = 0;
  report->cave_hash = 0;
  report->vmexit_hash = 0;
  report->anchor_valid_mask = 0;
  report->anchor_match_mask = 0;
  report->restore_count = 0;
  report->restore_readback_count = 0;
  report->carrier_cleared = 0;

  if (!size || (size & (FRAME - 1)) || scan_lo >= scan_hi || scan_hi > size) {
    error = 1;
    goto restore;
  }

  for (uint64_t off = 0; off < size; off += FRAME)
    mapped += bitmap_test(bitmap, off / FRAME, bitmap_bytes);

  if (hash_mapped_range(dmap, base, size, bitmap, bitmap_bytes,
                        code_base + CENSUS_BOUNDARY_OFFSET,
                        CENSUS_BOUNDARY_LENGTH,
                        &anchor_hash) == 0) {
    report->boundary_hash = anchor_hash;
    report->anchor_valid_mask |= 1;
    if (anchor_hash == CENSUS_BOUNDARY_FNV)
      report->anchor_match_mask |= 1;
  }
  if (hash_mapped_range(dmap, base, size, bitmap, bitmap_bytes,
                        code_base + CENSUS_CAVE_OFFSET,
                        CENSUS_CAVE_LENGTH,
                        &anchor_hash) == 0) {
    report->cave_hash = anchor_hash;
    report->anchor_valid_mask |= 2;
    if (anchor_hash == CENSUS_CAVE_FNV)
      report->anchor_match_mask |= 2;
  }
  if (hash_mapped_range(dmap, base, size, bitmap, bitmap_bytes,
                        code_base + CENSUS_VMEXIT_OFFSET,
                        CENSUS_VMEXIT_LENGTH,
                        &anchor_hash) == 0) {
    report->vmexit_hash = anchor_hash;
    report->anchor_valid_mask |= 4;
    if (anchor_hash == CENSUS_VMEXIT_FNV)
      report->anchor_match_mask |= 4;
  }
  if (report->anchor_valid_mask != 7) {
    error = 6;
    goto restore;
  }

  for (uint64_t off = scan_lo; off < scan_hi; off += FRAME) {
    if (!bitmap_test(bitmap, off / FRAME, bitmap_bytes)) {
      error = 2;
      continue;
    }
    const uint64_t pa = base + off;
    const volatile uint8_t *p =
        (const volatile uint8_t *)(uintptr_t)(dmap + pa);
    scanned++;
    if (load64(p + VMCB_GUEST_CR3) == needle_cr3 &&
        load64(p + VMCB_GUEST_RIP) == needle_rip) {
      if (self_count++ == 0) {
        self_pa = pa;
        self_nctl = load64(p + VMCB_NESTED_CTRL);
        self_ncr3 = load64(p + VMCB_NESTED_CR3);
        self_asid = load32(p + VMCB_ASID);
        self_iopm = load64(p + VMCB_IOPM_BASE_PA);
        self_msrpm = load64(p + VMCB_MSRPM_BASE_PA);
      }
    }
  }

  if (error == 0 && self_count != 1)
    error = 3;
  if (error == 0 &&
      (self_nctl != 9 || self_asid == 0 || self_asid >= 16 ||
       !valid_region_page(self_ncr3, base, size) ||
       !valid_region_page(self_iopm, base, size) ||
       !valid_region_page(self_msrpm, base, size)))
    error = 4;

  if (error == 0) {
    for (uint64_t off = scan_lo; off < scan_hi; off += FRAME) {
      const uint64_t pa = base + off;
      const volatile uint8_t *p =
          (const volatile uint8_t *)(uintptr_t)(dmap + pa);
      const uint64_t ncr3 = load64(p + VMCB_NESTED_CR3);
      const uint64_t iopm = load64(p + VMCB_IOPM_BASE_PA);
      if (load64(p + VMCB_NESTED_CTRL) == 9 &&
          load32(p + VMCB_ASID) == self_asid &&
          valid_region_page(ncr3, base, size) &&
          valid_region_page(iopm, base, size)) {
        if (recorded < CENSUS_CANDIDATE_MAX)
          report->candidate_pa[recorded++] = pa;
        targets++;
        before = candidate_hash(p, pa, before);
      }
    }
    if (targets != recorded)
      error = 5;
  }

  if (error == 0) {
    /* Hash the exact first-pass target addresses again.  Do not reselect a
     * potentially different set if a field changes between the two reads.
     * Each address was admitted only while its page's bitmap bit was set. */
    for (uint64_t i = 0; i < recorded; i++) {
      const uint64_t pa = report->candidate_pa[i];
      const volatile uint8_t *p =
          (const volatile uint8_t *)(uintptr_t)(dmap + pa);
      after = candidate_hash(p, pa, after);
    }
  }

restore:
  report->mapped_pages = mapped;
  report->scanned_pages = scanned;
  report->self_pa = self_pa;
  report->self_count = self_count;
  report->self_nctl = self_nctl;
  report->self_ncr3 = self_ncr3;
  report->self_asid = self_asid;
  report->self_iopm = self_iopm;
  report->self_msrpm = self_msrpm;
  report->target_count = targets;
  report->candidate_recorded = recorded;
  report->fields_hash_before = before;
  report->fields_hash_after = after;
  report->error = error;

  for (uint64_t cpu = 0; cpu < NCPU; cpu++) {
    volatile uint64_t *slot = (volatile uint64_t *)(uintptr_t)(
        tss_base + cpu * TSS_STRIDE + TSS_IST6);
    *slot = saved[cpu];
    report->restore_count++;
  }
  for (uint64_t cpu = 0; cpu < NCPU; cpu++) {
    const volatile uint64_t *slot = (const volatile uint64_t *)(uintptr_t)(
        tss_base + cpu * TSS_STRIDE + TSS_IST6);
    if (*slot == saved[cpu])
      report->restore_readback_count++;
  }
  *carrier_state = 0;
  report->carrier_cleared = *carrier_state == 0;
  report->state = CENSUS_STATE_DONE;
}
