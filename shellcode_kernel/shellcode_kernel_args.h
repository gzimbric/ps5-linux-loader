// This file is shared between main payload and kernel shellcode
#ifndef SHELLCODE_KERNEL_ARGS_H
#define SHELLCODE_KERNEL_ARGS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint16_t fw_version;
  uint64_t ktext;
  uint64_t kdata;
  uint64_t dmap_base;
  uint64_t fun_printf;
  uint64_t fun_hv_iommu_set_buffers;
  uint64_t fun_hv_iommu_wait_completion;
  uint64_t fun_smp_rendezvous;
  uint64_t fun_smp_no_rendevous_barrier;
  uint64_t fun_transmitter_control;
  uint64_t fun_mp3_initialize;
  uint64_t fun_mp3_invoke;
  uint64_t g_vbios;
  uint64_t iommu_softc;
  uint64_t kernel_uart_override;
  uint64_t kernel_cfi_check;
  uint64_t hv_handle_vmexit_pa;
  uint64_t hv_code_cave_pa;
  uint64_t linux_info_va; // To relocate by kernel shellcode
} shellcode_kernel_args;

/*
 * This layout is the public wake-shellcode ABI.  In particular, the 13.60
 * reference image uses the same 0x98-byte argument block.  Keep these
 * assertions exhaustive: an innocent field insertion must not silently
 * produce a blob that interprets an older argument block differently.
 */
_Static_assert(offsetof(shellcode_kernel_args, fw_version) == 0x00,
               "shellcode args ABI: fw_version");
_Static_assert(offsetof(shellcode_kernel_args, ktext) == 0x08,
               "shellcode args ABI: ktext");
_Static_assert(offsetof(shellcode_kernel_args, kdata) == 0x10,
               "shellcode args ABI: kdata");
_Static_assert(offsetof(shellcode_kernel_args, dmap_base) == 0x18,
               "shellcode args ABI: dmap_base");
_Static_assert(offsetof(shellcode_kernel_args, fun_printf) == 0x20,
               "shellcode args ABI: fun_printf");
_Static_assert(offsetof(shellcode_kernel_args, fun_hv_iommu_set_buffers) ==
                   0x28,
               "shellcode args ABI: fun_hv_iommu_set_buffers");
_Static_assert(offsetof(shellcode_kernel_args,
                        fun_hv_iommu_wait_completion) == 0x30,
               "shellcode args ABI: fun_hv_iommu_wait_completion");
_Static_assert(offsetof(shellcode_kernel_args, fun_smp_rendezvous) == 0x38,
               "shellcode args ABI: fun_smp_rendezvous");
_Static_assert(offsetof(shellcode_kernel_args,
                        fun_smp_no_rendevous_barrier) == 0x40,
               "shellcode args ABI: fun_smp_no_rendevous_barrier");
_Static_assert(offsetof(shellcode_kernel_args, fun_transmitter_control) ==
                   0x48,
               "shellcode args ABI: fun_transmitter_control");
_Static_assert(offsetof(shellcode_kernel_args, fun_mp3_initialize) == 0x50,
               "shellcode args ABI: fun_mp3_initialize");
_Static_assert(offsetof(shellcode_kernel_args, fun_mp3_invoke) == 0x58,
               "shellcode args ABI: fun_mp3_invoke");
_Static_assert(offsetof(shellcode_kernel_args, g_vbios) == 0x60,
               "shellcode args ABI: g_vbios");
_Static_assert(offsetof(shellcode_kernel_args, iommu_softc) == 0x68,
               "shellcode args ABI: iommu_softc");
_Static_assert(offsetof(shellcode_kernel_args, kernel_uart_override) == 0x70,
               "shellcode args ABI: kernel_uart_override");
_Static_assert(offsetof(shellcode_kernel_args, kernel_cfi_check) == 0x78,
               "shellcode args ABI: kernel_cfi_check");
_Static_assert(offsetof(shellcode_kernel_args, hv_handle_vmexit_pa) == 0x80,
               "shellcode args ABI: hv_handle_vmexit_pa");
_Static_assert(offsetof(shellcode_kernel_args, hv_code_cave_pa) == 0x88,
               "shellcode args ABI: hv_code_cave_pa");
_Static_assert(offsetof(shellcode_kernel_args, linux_info_va) == 0x90,
               "shellcode args ABI: linux_info_va");
_Static_assert(sizeof(shellcode_kernel_args) == 0x98,
               "shellcode args ABI must remain 0x98 bytes");

extern shellcode_kernel_args args; // Declared on main.c

#endif
