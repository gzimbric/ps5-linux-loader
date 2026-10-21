#ifndef SHELLCODE_KERNEL_ARGS_VALIDATE_H
#define SHELLCODE_KERNEL_ARGS_VALIDATE_H

#include "shellcode_kernel_args.h"

#define PS5_FW_1160 0x1160U

static inline int shellcode_kernel_va_is_canonical(uint64_t va) {
  return va >= UINT64_C(0xffff800000000000);
}

/*
 * Fail-closed preflight for the exact 11.60 candidate.  UART remains optional
 * because retail testing is intentionally UART-free.  Sonic's VBIOS,
 * transmitter, and MP3 display-handoff inputs are mandatory: the wake path
 * must never silently degrade back to the known-black-screen headless build.
 */
static inline int validate_shellcode_kernel_args_1160(
    volatile const shellcode_kernel_args *candidate) {
  if (candidate == NULL || candidate->fw_version != PS5_FW_1160)
    return -1;

  if (!shellcode_kernel_va_is_canonical(candidate->ktext) ||
      !shellcode_kernel_va_is_canonical(candidate->kdata) ||
      !shellcode_kernel_va_is_canonical(candidate->dmap_base) ||
      candidate->kdata <= candidate->ktext)
    return -1;

  if ((candidate->ktext & 0x3fffU) != 0 ||
      (candidate->kdata & 0x3fffU) != 0 ||
      (candidate->dmap_base & 0x3fffU) != 0 ||
      (candidate->linux_info_va & 0x3fffU) != 0)
    return -1;

  if (!shellcode_kernel_va_is_canonical(candidate->fun_printf) ||
      !shellcode_kernel_va_is_canonical(candidate->fun_smp_rendezvous) ||
      !shellcode_kernel_va_is_canonical(
          candidate->fun_smp_no_rendevous_barrier) ||
      !shellcode_kernel_va_is_canonical(candidate->kernel_cfi_check) ||
      !shellcode_kernel_va_is_canonical(candidate->g_vbios) ||
      !shellcode_kernel_va_is_canonical(
          candidate->fun_transmitter_control) ||
      !shellcode_kernel_va_is_canonical(candidate->fun_mp3_initialize) ||
      !shellcode_kernel_va_is_canonical(candidate->fun_mp3_invoke) ||
      !shellcode_kernel_va_is_canonical(candidate->linux_info_va))
    return -1;

  if (candidate->hv_handle_vmexit_pa == 0 ||
      candidate->hv_code_cave_pa == 0 || candidate->linux_info_va == 0)
    return -1;

  return 0;
}

#endif
