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
  candidate.g_vbios = candidate.ktext + 0x5001;
  candidate.fun_transmitter_control = candidate.ktext + 0x6001;
  candidate.fun_mp3_initialize = candidate.ktext + 0x7001;
  candidate.fun_mp3_invoke = candidate.ktext + 0x8001;
  candidate.hv_handle_vmexit_pa = 0x1001;
  candidate.hv_code_cave_pa = 0x2001;
  candidate.linux_info_va = UINT64_C(0xffff80000000c000);
  return candidate;
}

int main(void) {
  shellcode_kernel_args candidate = valid_candidate();

  assert(sizeof(candidate) == 0x98);
  assert(validate_shellcode_kernel_args_1160(&candidate) == 0);

  /* Retail UART remains optional; the display handoff does not. */
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
  candidate = valid_candidate();
  candidate.g_vbios = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.fun_transmitter_control = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.fun_mp3_initialize = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.fun_mp3_invoke = 0;
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.g_vbios = UINT64_C(0xffff000000000000);
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);
  candidate = valid_candidate();
  candidate.linux_info_va = UINT64_C(0xffff7fffffffc000);
  assert(validate_shellcode_kernel_args_1160(&candidate) != 0);

  return 0;
}
