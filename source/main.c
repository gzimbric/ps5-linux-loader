#include "hv_defeat_0304.h"
#include "hv_defeat_0506.h"
#include "hv_defeat_0607.h"
#if FW_1160_PORT
#include "hv_defeat_1160.h"
#endif
#include "config.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <unistd.h>

#define PS5_PRO_SOC_ID 0x840fd0

int main(void) {
#if STAGE2A_1160 || FW_1160_PORT
  /* This read-only raw gate precedes notifications and all state changes. */
  if (kernel_get_fw_version() != 0x11600005U) {
    notify("11.60 loader refused: exact retail firmware required\n");
    return -1;
  }
#endif

#if FW_1160_PORT
  /* The proven 11.60 AP donor uses the regular-model HV physical layout. */
  if (sceKernelGetMainSocId() == PS5_PRO_SOC_ID) {
    notify("11.60 loader refused: PS5 Pro HV layout is not validated\n");
    return -1;
  }
#endif

  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }

#if STAGE2A_1160
  if (fw != 0x1160) {
    notify("11.60 Stage 2A refused: exact firmware required\n");
    return -1;
  }

  /* Required nonzero future ABI address; Stage 2A never dereferences it. */
  linux_i.linux_info = kernel_cave_linux_info;

  void *shellcode_kernel;
  size_t shellcode_kernel_len;
  if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
    notify("11.60 Stage 2A failed before arming anything\n");
    return -1;
  }

  notify("11.60 Stage 2A is holding the verified backing page. GameOS should "
         "remain responsive. Cold reboot after recording the result.\n");
  while (1)
    sleep(30);
#else

  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }

  void *shellcode_kernel;
  size_t shellcode_kernel_len;
  if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
    notify("Something went wrong while preparing resume.\n");
    return -1;
  }

#if FW_1160_PORT
  if (fw == 0x1160) {
    if (hv_defeat_1160(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else {
    goto err;
  }
#else
  if ((0x0300 <= fw) && (fw < 0x0500)) {
    if (hv_defeat_0304(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0500 <= fw) && (fw < 0x0650)) {
    if (hv_defeat_0506(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0650 <= fw) && (fw < 0x0800)) {
    if (hv_defeat_0607(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else {
    goto err;
  }
#endif

  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  sleep(5);
  enter_rest_mode();

  while (1) {
    sleep(30);
  }

  return 0;

err:
  notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
         "your fw is supported.");
  return -1;
#endif
}
