#ifndef SHELLCODE_KERNEL_ARGS_VALIDATE_H
#define SHELLCODE_KERNEL_ARGS_VALIDATE_H

#include "shellcode_kernel_args.h"

#define PS5_FW_1160 0x1160U

static inline int shellcode_kernel_va_is_canonical(uint64_t va) {
  return (va >> 48) == 0xffffU;
}

/*
 * Fail-closed preflight for the exact 11.60 candidate.  Display/UART fields
 * are deliberately optional for headless operation.  The remaining fields
 * are inputs to mutations in the public wake path and therefore must be
 * present before that path can ever be armed.
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
      (candidate->dmap_base & 0x3fffU) != 0)
    return -1;

  if (!shellcode_kernel_va_is_canonical(candidate->fun_printf) ||
      !shellcode_kernel_va_is_canonical(candidate->fun_smp_rendezvous) ||
      !shellcode_kernel_va_is_canonical(
          candidate->fun_smp_no_rendevous_barrier) ||
      !shellcode_kernel_va_is_canonical(candidate->kernel_cfi_check))
    return -1;

  if (candidate->hv_handle_vmexit_pa == 0 ||
      candidate->hv_code_cave_pa == 0 || candidate->linux_info_va == 0)
    return -1;

  return 0;
}

#endif
