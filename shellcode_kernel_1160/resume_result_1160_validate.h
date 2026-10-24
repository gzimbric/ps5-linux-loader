#ifndef RESUME_RESULT_1160_VALIDATE_H
#define RESUME_RESULT_1160_VALIDATE_H

#include "shellcode_kernel_args_validate.h"
#include <stdint.h>

#define RESUME_DATA_CAVE_1160 0x2d02000ULL
#define RESUME_ORACLE_OFF_1160 0x440ULL
#define RESUME_RESULT_OFF_1160 0x3600ULL

#define RESUME_MARK_ENTERED_1160 0x454e544552454431ULL
#define RESUME_MARK_DONE_1160    0x444f4e452d415031ULL
#define RESUME_MODE_STRIKE_1160  0x31454b4952545356ULL

#define RESUME_REGULAR_SCAN_LO_1160 0x062a00000ULL
#define RESUME_REGULAR_SCAN_HI_1160 0x063800000ULL
#define RESUME_PRO_SCAN_LO_1160     0x8e0a00000ULL
#define RESUME_PRO_SCAN_HI_1160     0x8e1800000ULL
#define RESUME_PRO_REGION_LO_1160   0x8e0000000ULL
#define RESUME_PRO_REGION_HI_1160   0x8e2000000ULL

#define RESUME_TARGETS_1160 16

static inline int resume_result_page_1160(uint64_t pa, uint64_t lo,
                                          uint64_t hi) {
  return (pa & 0xfffULL) == 0 && pa >= lo && pa < hi;
}

/* Validate the complete AP commit record before the wake blob mutates CFI,
 * VMEXIT, or Linux staging state. The addresses are selected only by the
 * already-validated regular/Pro HV pair; no console-specific VMCB bank is
 * compiled into the loader. */
static inline int validate_resume_result_1160(
    uint16_t fw_version, uint64_t ktext, uint64_t hv_vmexit_pa,
    uint64_t hv_cave_pa) {
  const volatile uint64_t *oracle =
      (const volatile uint64_t *)(uintptr_t)(
          ktext + RESUME_DATA_CAVE_1160 + RESUME_ORACLE_OFF_1160);
  const volatile uint64_t *ext =
      (const volatile uint64_t *)(uintptr_t)(
          ktext + RESUME_DATA_CAVE_1160 + RESUME_RESULT_OFF_1160);
  uint64_t scan_lo, scan_hi, pointer_lo, pointer_hi;
  int pro;

  if ((fw_version == 0x1100 || fw_version == 0x1120 ||
       fw_version == 0x1140 || fw_version == 0x1160) &&
      hv_vmexit_pa == HV_VMEXIT_REGULAR_1160 &&
      hv_cave_pa == HV_CAVE_REGULAR_1160) {
    scan_lo = RESUME_REGULAR_SCAN_LO_1160;
    scan_hi = RESUME_REGULAR_SCAN_HI_1160;
    pointer_lo = scan_lo;
    pointer_hi = scan_hi;
    pro = 0;
  } else if (fw_version == 0x1160 &&
             hv_vmexit_pa == HV_VMEXIT_PRO_1160 &&
             hv_cave_pa == HV_CAVE_PRO_1160) {
    scan_lo = RESUME_PRO_SCAN_LO_1160;
    scan_hi = RESUME_PRO_SCAN_HI_1160;
    pointer_lo = RESUME_PRO_REGION_LO_1160;
    pointer_hi = RESUME_PRO_REGION_HI_1160;
    pro = 1;
  } else {
    return -1;
  }

  if (oracle[0] != RESUME_MARK_ENTERED_1160 ||
      oracle[1] != RESUME_MODE_STRIKE_1160 ||
      oracle[3] != RESUME_MARK_DONE_1160 || oracle[5] != 0 ||
      oracle[6] != RESUME_TARGETS_1160 ||
      oracle[7] != RESUME_TARGETS_1160 || ext[0] != 0 ||
      ext[1] == 0 || ext[1] != oracle[2] || ext[2] != 1 ||
      ext[3] != RESUME_TARGETS_1160 || ext[5] == 0 || ext[5] >= 16 ||
      !resume_result_page_1160(ext[4], pointer_lo, pointer_hi) ||
      !resume_result_page_1160(ext[6], pointer_lo, pointer_hi) ||
      (pro && !resume_result_page_1160(ext[7], pointer_lo, pointer_hi)) ||
      ext[8] != RESUME_TARGETS_1160 || ext[9] != RESUME_TARGETS_1160 ||
      ext[26] != 0 || ext[27] != 0 || ext[28] != ext[29])
    return -1;

  int self_matches = 0;
  for (int i = 0; i < RESUME_TARGETS_1160; i++) {
    const uint64_t candidate = ext[10 + i];
    if (!resume_result_page_1160(candidate, scan_lo, scan_hi))
      return -1;
    if (candidate == ext[1])
      self_matches++;
    for (int prior = 0; prior < i; prior++)
      if (candidate == ext[10 + prior])
        return -1;
  }
  return self_matches == 1 ? 0 : -1;
}

#endif
