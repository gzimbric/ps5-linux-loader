#ifndef HV_DEFEAT_1160_H
#define HV_DEFEAT_1160_H

#include "config.h"
#include <stddef.h>
#include <stdint.h>

struct pro_hv_layout_1160 {
  uint64_t region_base;
  uint64_t region_size;
  uint64_t code_base;
  uint64_t relocation;
  uint64_t scan_lo;
  uint64_t scan_hi;
  uint64_t pointer_lo;
  uint64_t pointer_hi;
  uint64_t vmexit_pa;
  uint64_t cave_pa;
};

/*
 * The Pro relocation method treats the regular and Pro HV images as the same
 * layout at different physical bases.  Keep the arithmetic independent from the
 * metadata reader so it can be tested on the host before an ELF reaches a
 * console.  The caller remains responsible for validating the discovered
 * region against the firmware-specific evidence.
 */
static inline int calculate_pro_hv_layout_1160(
    uint64_t region_base, uint64_t region_size, uint64_t regular_vmexit_pa,
    uint64_t regular_cave_pa, struct pro_hv_layout_1160 *layout) {
  const uint64_t regular_scan_lo = HV_BASE_REGULAR + UINT64_C(0x200000);
  const uint64_t regular_scan_hi = HV_BASE_REGULAR + UINT64_C(0x1000000);
  uint64_t code_base, relocation;

  if (layout == NULL || region_size != HV_REGION_SIZE_PRO ||
      (region_base & UINT64_C(0xfff)) != 0 ||
      region_base > UINT64_MAX - region_size ||
      region_base > UINT64_MAX - HV_CODE_OFFSET_PRO)
    return -1;

  code_base = region_base + HV_CODE_OFFSET_PRO;
  if (code_base < HV_BASE_REGULAR || regular_vmexit_pa < HV_BASE_REGULAR ||
      regular_cave_pa < HV_BASE_REGULAR)
    return -1;
  relocation = code_base - HV_BASE_REGULAR;

  if (regular_scan_lo > UINT64_MAX - relocation ||
      regular_scan_hi > UINT64_MAX - relocation ||
      regular_vmexit_pa > UINT64_MAX - relocation ||
      regular_cave_pa > UINT64_MAX - relocation)
    return -1;

  *layout = (struct pro_hv_layout_1160){
      .region_base = region_base,
      .region_size = region_size,
      .code_base = code_base,
      .relocation = relocation,
      .scan_lo = regular_scan_lo + relocation,
      .scan_hi = regular_scan_hi + relocation,
      .pointer_lo = region_base,
      .pointer_hi = region_base + region_size,
      .vmexit_pa = regular_vmexit_pa + relocation,
      .cave_pa = regular_cave_pa + relocation,
  };

  if (layout->scan_lo < layout->pointer_lo ||
      layout->scan_hi > layout->pointer_hi ||
      layout->scan_lo >= layout->scan_hi ||
      layout->vmexit_pa < layout->code_base ||
      layout->vmexit_pa >= layout->pointer_hi ||
      layout->cave_pa < layout->code_base ||
      layout->cave_pa >= layout->pointer_hi)
    return -1;

  return 0;
}

/* Resolve and validate the live 11.60 Pro region before any HV mutation. */
int resolve_pro_hv_layout_1160(struct pro_hv_layout_1160 *layout);

int hv_defeat_1160(void *shellcode_kernel, size_t shellcode_kernel_len);

#endif
