#include "../shellcode_kernel/shellcode_kernel_args_validate.h"
#include <assert.h>
#include <stdint.h>

static shellcode_kernel_args valid_candidate(void) {
  shellcode_kernel_args candidate = {0};
  candidate.fw_version = PS5_FW_1160;
  candidate.ktext = UINT64_C(0xffffffff80000000);
  candidate.kdata = UINT64_C(0xffffffff82000000);
  candidate.dmap_base = UINT64_C(0xffff800000000000);
  candidate.fun_printf = candidate.ktext + 0x1001;
  candidate.fun_smp_rendezvous = candidate.ktext + 0x2001;
  candidate.fun_smp_no_rendevous_barrier = candidate.ktext + 0x3001;
  candidate.kernel_cfi_check = candidate.ktext + 0x4001;
  candidate.hv_handle_vmexit_pa = 0x1001;
  candidate.hv_code_cave_pa = 0x2001;
  candidate.linux_info_va = 0x3001;
  return candidate;
}

int main(void) {
  shellcode_kernel_args candidate = valid_candidate();

  assert(sizeof(candidate) == 0x98);
  assert(validate_shellcode_kernel_args_1160(&candidate) == 0);

  /* Headless optional fields are allowed to remain NULL. */
  assert(candidate.g_vbios == 0);
  assert(candidate.fun_transmitter_control == 0);
  assert(candidate.fun_mp3_initialize == 0);
  assert(candidate.fun_mp3_invoke == 0);
  assert(candidate.kernel_uart_override == 0);

  candidate.fw_version = 0x1360;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.fun_smp_rendezvous = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.hv_code_cave_pa = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.ktext |= 1;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.linux_info_va = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);

  return 0;
}
