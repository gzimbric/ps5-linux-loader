#include "shellcode_kernel_args_validate.h"
#include <stdint.h>

/*
 * Inert exact-11.60 wake candidate. The marker is patched to the address of
 * the public 0x98-byte argument block by the outer loader. This entry performs
 * validation and returns; it deliberately contains no mutation or boot path.
 */
__attribute__((section(".entry_point"))) uint32_t
wake_1160_entry(uint64_t argument_1, uint64_t argument_2) {
  (void)argument_1;
  (void)argument_2;

  volatile const shellcode_kernel_args *args_ptr =
      (volatile const shellcode_kernel_args *)UINT64_C(0x11AA11AA11AA11AA);
  __asm__ volatile("" : "+r"(args_ptr));

  if (args_ptr->fw_version != PS5_FW_1160)
    return UINT32_MAX;

  if (validate_shellcode_kernel_args_1160(args_ptr) != 0)
    return UINT32_MAX;

  return 0;
}
