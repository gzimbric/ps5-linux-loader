#include "main.h"
#include "boot_linux.h"
#if SHELLCODE_1160_ONLY
#include "display_ops_1160.h"
#endif
#if !SHELLCODE_1160_ONLY
#include "hv_defeat_0304.h"
#endif
#include "shellcode_kernel_args_validate.h"
#include "resume_result_1160_validate.h"
#include "utils.h"
#include <stddef.h>

shellcode_kernel_args args = {0};

#if SHELLCODE_1160_ONLY
/* The 11.60 wake blob is entered by a one-way ROP ret, not a C caller.  An
 * error path must never execute a function epilogue and consume stale IST
 * stack data as a return address.  Stop this CPU before any later mutation;
 * recovery is the already-required cold reboot. */
__attribute__((noreturn)) static void hold_for_cold_reboot_1160(void) {
  for (;;)
    __asm__ volatile("cli; hlt" ::: "memory");
}
#endif

// We are being called instead of AcpiSetFirmwareWakingVector
__attribute__((section(".entry_point"))) uint32_t main(uint64_t add1,
                                                       uint64_t add2) {
  (void)add1;
  (void)add2;

  // We will do main checks on .text only with a reference to .data
  volatile shellcode_kernel_args *args_ptr =
      (volatile shellcode_kernel_args
           *)0x11AA11AA11AA11AA; // To be replaced with proper address in .kdata

  // "Hide" the pointer from the optimizer
  __asm__ volatile("" : "+r"(args_ptr));

#if SHELLCODE_1160_ONLY
  /* 11.60 arrives here only after the startup-AP payload disabled NPT. */
  if (validate_shellcode_kernel_args_1160(args_ptr) != 0)
    hold_for_cold_reboot_1160();
  activate_uart(args_ptr);
  init_global_pointers(args_ptr);
  if (validate_resume_result_1160(args.ktext, args.hv_handle_vmexit_pa,
                                  args.hv_code_cave_pa) != 0) {
    printf("11.60 startup-AP result refused\n");
    hold_for_cold_reboot_1160();
  }
  *(uint8_t *)args_ptr->kernel_cfi_check = 0xC3;
  boot_linux();
  run_ps5_display_ops_1160();
  printf("Linux prepared OK\n");
  printf("Good Bye VM :)\n");
  smp_rendezvous(smp_no_rendevous_barrier, vmmcall_dummy,
                 smp_no_rendevous_barrier, NULL);
  hold_for_cold_reboot_1160();
#else

  // We don't have required information - Abort
  if ((args_ptr->fun_printf & 0xFFFF) == 0) {
    return -1;
  }

  activate_uart(args_ptr);

  if ((0x0300 <= args_ptr->fw_version) && (args_ptr->fw_version < 0x0500)) {
    if (hv_defeat_0304(args_ptr))
      return -1;
  } else if ((0x0500 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x0800)) {
    // Already escaped.
  } else {
    return 0;
  }

  // Now we can R/W on .text
  init_global_pointers(args_ptr);

  // Disable CFI to allow smp_rendezvous.
  *(uint8_t *)args_ptr->kernel_cfi_check = 0xC3;

  boot_linux();
  printf("Linux prepared OK\n");

  printf("Good Bye VM :)\n");
  smp_rendezvous(smp_no_rendevous_barrier, vmmcall_dummy,
                 smp_no_rendevous_barrier, NULL);

  printf("We shouldn't be here :(\n");
  return 0;
#endif
}
