#include "../include/hv_defeat_1160.h"
#include "../shellcode_kernel/shellcode_kernel_args_validate.h"

#include <assert.h>
#include <stdint.h>

int main(void) {
  struct pro_hv_layout_1160 layout = {0};

  assert(calculate_pro_hv_layout_1160(
             HV_REGION_BASE_PRO, HV_REGION_SIZE_PRO,
             HV_VMEXIT_REGULAR_1160, HV_CAVE_REGULAR_1160, &layout) == 0);
  assert(layout.region_base == UINT64_C(0x8e0000000));
  assert(layout.region_size == UINT64_C(0x2000000));
  assert(layout.code_base == HV_CODE_BASE_PRO_1160);
  assert(layout.relocation == UINT64_C(0x87e000000));
  assert(layout.scan_lo == UINT64_C(0x8e0a00000));
  assert(layout.scan_hi == UINT64_C(0x8e1800000));
  assert(layout.pointer_lo == UINT64_C(0x8e0000000));
  assert(layout.pointer_hi == UINT64_C(0x8e2000000));
  assert(layout.vmexit_pa == HV_VMEXIT_PRO_1160);
  assert(layout.cave_pa == HV_CAVE_PRO_1160);

  /* Prove that the helper performs a relocation rather than selecting a
   * second compiled-in address pair. Runtime code still pins 11.60 to its
   * authenticated region before accepting these results. */
  assert(calculate_pro_hv_layout_1160(
             UINT64_C(0x9e0000000), HV_REGION_SIZE_PRO,
             HV_VMEXIT_REGULAR_1160, HV_CAVE_REGULAR_1160, &layout) == 0);
  assert(layout.relocation == UINT64_C(0x97e000000));
  assert(layout.scan_lo == UINT64_C(0x9e0a00000));
  assert(layout.scan_hi == UINT64_C(0x9e1800000));
  assert(layout.vmexit_pa == UINT64_C(0x9e0847551));
  assert(layout.cave_pa == UINT64_C(0x9e0806f00));

  assert(calculate_pro_hv_layout_1160(
             HV_REGION_BASE_PRO + 1, HV_REGION_SIZE_PRO,
             HV_VMEXIT_REGULAR_1160, HV_CAVE_REGULAR_1160, &layout) != 0);
  assert(calculate_pro_hv_layout_1160(
             HV_REGION_BASE_PRO, HV_REGION_SIZE_PRO - UINT64_C(0x1000),
             HV_VMEXIT_REGULAR_1160, HV_CAVE_REGULAR_1160, &layout) != 0);
  assert(calculate_pro_hv_layout_1160(
             UINT64_MAX - UINT64_C(0xfff), HV_REGION_SIZE_PRO,
             HV_VMEXIT_REGULAR_1160, HV_CAVE_REGULAR_1160, &layout) != 0);
  assert(calculate_pro_hv_layout_1160(
             HV_REGION_BASE_PRO, HV_REGION_SIZE_PRO, HV_BASE_REGULAR - 1,
             HV_CAVE_REGULAR_1160, &layout) != 0);
  assert(calculate_pro_hv_layout_1160(
             HV_REGION_BASE_PRO, HV_REGION_SIZE_PRO,
             HV_VMEXIT_REGULAR_1160, HV_CAVE_REGULAR_1160, NULL) != 0);

  return 0;
}
