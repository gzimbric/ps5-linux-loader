#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "../shellcode_kernel_1160/resume_result_1160_validate.h"

static void prepare_success(uint8_t *cave, int pro) {
  uint64_t *oracle = (uint64_t *)(cave + RESUME_ORACLE_OFF_1160);
  uint64_t *ext = (uint64_t *)(cave + RESUME_RESULT_OFF_1160);
  const uint64_t scan_lo =
      pro ? RESUME_PRO_SCAN_LO_1160 : RESUME_REGULAR_SCAN_LO_1160;
  const uint64_t pointer_lo =
      pro ? RESUME_PRO_REGION_LO_1160 : RESUME_REGULAR_SCAN_LO_1160;

  oracle[0] = RESUME_MARK_ENTERED_1160;
  oracle[1] = RESUME_MODE_STRIKE_1160;
  oracle[2] = scan_lo + 0x1000;
  oracle[3] = RESUME_MARK_DONE_1160;
  oracle[5] = 0;
  oracle[6] = RESUME_TARGETS_1160;
  oracle[7] = RESUME_TARGETS_1160;

  ext[0] = 0;
  ext[1] = oracle[2];
  ext[2] = 1;
  ext[3] = RESUME_TARGETS_1160;
  ext[4] = pointer_lo + 0x7000;
  ext[5] = 1;
  ext[6] = pointer_lo + 0x9000;
  ext[7] = pro ? pointer_lo + 0xb000 : 0;
  ext[8] = RESUME_TARGETS_1160;
  ext[9] = RESUME_TARGETS_1160;
  for (int i = 0; i < RESUME_TARGETS_1160; i++)
    ext[10 + i] = scan_lo + 0x1000 + (uint64_t)i * 0x2000;
  ext[26] = 0;
  ext[27] = 0;
  ext[28] = UINT64_C(0x123456789abcdef0);
  ext[29] = ext[28];
}

static int validate(uint8_t *cave, uint16_t fw_version, int pro) {
  const uint64_t ktext =
      (uint64_t)(uintptr_t)cave - RESUME_DATA_CAVE_1160;
  return validate_resume_result_1160(
      fw_version, ktext,
      pro ? HV_VMEXIT_PRO_1160 : HV_VMEXIT_REGULAR_1160,
      pro ? HV_CAVE_PRO_1160 : HV_CAVE_REGULAR_1160);
}

static void run_variant(int pro) {
  uint8_t *cave = calloc(1, 0x4000);
  assert(cave != NULL);
  prepare_success(cave, pro);
  assert(validate(cave, 0x1160, pro) == 0);

  uint64_t *oracle = (uint64_t *)(cave + RESUME_ORACLE_OFF_1160);
  uint64_t *ext = (uint64_t *)(cave + RESUME_RESULT_OFF_1160);

  oracle[3] = 0;
  assert(validate(cave, 0x1160, pro) != 0);
  oracle[3] = RESUME_MARK_DONE_1160;

  ext[0] = 6;
  assert(validate(cave, 0x1160, pro) != 0);
  ext[0] = 0;

  ext[3] = 15;
  assert(validate(cave, 0x1160, pro) != 0);
  ext[3] = RESUME_TARGETS_1160;

  ext[27] = 1;
  assert(validate(cave, 0x1160, pro) != 0);
  ext[27] = 0;

  ext[29] ^= 1;
  assert(validate(cave, 0x1160, pro) != 0);
  ext[29] = ext[28];

  ext[11] = ext[10];
  assert(validate(cave, 0x1160, pro) != 0);
  prepare_success(cave, pro);

  oracle[2] = ext[10] + 0x1000;
  ext[1] = oracle[2];
  assert(validate(cave, 0x1160, pro) != 0);

  free(cave);
}

int main(void) {
  run_variant(0);
  run_variant(1);

  uint8_t *cave = calloc(1, 0x4000);
  assert(cave != NULL);
  prepare_success(cave, 1);
  assert(validate(cave, 0x1140, 1) != 0);

  const uint64_t ktext =
      (uint64_t)(uintptr_t)cave - RESUME_DATA_CAVE_1160;
  assert(validate_resume_result_1160(0x1160, ktext, HV_VMEXIT_PRO_1160,
                                     HV_CAVE_REGULAR_1160) != 0);
  free(cave);
  return 0;
}
