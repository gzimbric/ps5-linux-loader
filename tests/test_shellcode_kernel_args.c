#include "../shellcode_kernel_1160/shellcode_kernel_args_validate.h"

#include <assert.h>
#include <stdint.h>

static shellcode_kernel_args valid_candidate(uint16_t fw_version) {
  shellcode_kernel_args candidate = {0};
  candidate.fw_version = fw_version;
  candidate.ktext = UINT64_C(0xffffffff80000000);
  candidate.kdata = UINT64_C(0xffffffff82000000);
  candidate.dmap_base = UINT64_C(0xffff800000000000);
  candidate.fun_printf = candidate.ktext + 0x1001;
  candidate.fun_smp_rendezvous = candidate.ktext + 0x2001;
  candidate.fun_smp_no_rendevous_barrier = candidate.ktext + 0x3001;
  candidate.kernel_cfi_check = candidate.ktext + 0x4001;
  candidate.g_vbios = candidate.ktext + 0x5001;
  candidate.fun_transmitter_control = candidate.ktext + 0x6001;
  candidate.fun_mp3_initialize = candidate.ktext + 0x7001;
  candidate.fun_mp3_invoke = candidate.ktext + 0x8001;
  candidate.hv_handle_vmexit_pa = HV_VMEXIT_REGULAR_1160;
  candidate.hv_code_cave_pa = HV_CAVE_REGULAR_1160;
  candidate.linux_info_va = UINT64_C(0xffff80000000c000);
  return candidate;
}

int main(void) {
  static const uint16_t regular_firmware[] = {0x1100, 0x1120, 0x1140, 0x1160};

  for (unsigned i = 0; i < sizeof(regular_firmware) / sizeof(regular_firmware[0]);
       i++) {
    shellcode_kernel_args candidate = valid_candidate(regular_firmware[i]);
    assert(validate_shellcode_kernel_args_1160(&candidate) == 0);
  }

  shellcode_kernel_args candidate = valid_candidate(0x1160);
  assert(sizeof(candidate) == 0x98);
  candidate.hv_handle_vmexit_pa = HV_VMEXIT_PRO_1160;
  candidate.hv_code_cave_pa = HV_CAVE_PRO_1160;
  assert(validate_shellcode_kernel_args_1160(&candidate) == 0);

  /* The Pro address pair is exact and is valid only on 11.60. */
  candidate.fw_version = 0x1140;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate(0x1160);
  candidate.hv_handle_vmexit_pa = UINT64_C(0x8e0847540);
  candidate.hv_code_cave_pa = UINT64_C(0x8e0806ec0);
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate.hv_handle_vmexit_pa = UINT64_C(0x8e0847540);
  candidate.hv_code_cave_pa = HV_CAVE_PRO_1160;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate.hv_handle_vmexit_pa = HV_VMEXIT_PRO_1160;
  candidate.hv_code_cave_pa = UINT64_C(0x8e0806ec0);
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);

  /* Never accept a mixed regular/Pro pair. */
  candidate = valid_candidate(0x1160);
  candidate.hv_handle_vmexit_pa = HV_VMEXIT_PRO_1160;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate(0x1160);
  candidate.hv_code_cave_pa = HV_CAVE_PRO_1160;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);

  candidate = valid_candidate(0x1160);
  candidate.fw_version = 0x1360;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate(0x1160);
  candidate.ktext |= 1;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate(0x1160);
  candidate.fun_smp_rendezvous = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate(0x1160);
  candidate.linux_info_va = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);

  return 0;
}
