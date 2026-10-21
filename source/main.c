#include "hv_defeat_0304.h"
#include "hv_defeat_0506.h"
#include "hv_defeat_0607.h"
#if FW_1160_PORT
#include "hv_defeat_1160.h"
#endif
#include "hv_defeat_13xx.h"
#include "config.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#if FW_1160_PORT
#include <stdio.h>
#endif
#include <unistd.h>

#define PS5_PRO_SOC_ID 0x840fd0

#if FW_1160_PORT
static void checkpoint_1160_main(const char *stage) {
  if (fw != 0x1160)
    return;
  printf("11.60 checkpoint: main: %s\n", stage);
  fflush(stdout);
}

[[noreturn]] static void hold_1160_after_staging_failure(const char *stage) {
  printf("11.60 checkpoint: main: %s failed; retaining all backing until "
         "cold reboot\n",
         stage);
  fflush(stdout);
  notify("11.60 stopped after Linux staging. Cold reboot required; do not "
         "retry this boot.\n");
  while (1)
    sleep(30);
}
#endif

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

#if FW_1160_PORT
  checkpoint_1160_main("fetch_linux call");
  int fetch_linux_result = fetch_linux(&linux_i);
  printf("11.60 checkpoint: main: fetch_linux returned %d\n",
         fetch_linux_result);
  fflush(stdout);
  if (fetch_linux_result) {
#else
  if (fetch_linux(&linux_i)) {
#endif
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }

  void *shellcode_kernel;
  size_t shellcode_kernel_len;
#if FW_1160_PORT
  checkpoint_1160_main("prepare_resume call");
  int prepare_resume_result =
      prepare_resume(&shellcode_kernel, &shellcode_kernel_len);
  printf("11.60 checkpoint: main: prepare_resume returned %d\n",
         prepare_resume_result);
  fflush(stdout);
  if (prepare_resume_result) {
#else
  if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
#endif
    notify("Something went wrong while preparing resume.\n");
#if FW_1160_PORT
    hold_1160_after_staging_failure("prepare_resume");
#else
    return -1;
#endif
  }

#if FW_1160_PORT
  if (fw == 0x1160) {
    checkpoint_1160_main("hv_defeat_1160 call");
    int hv_defeat_result =
        hv_defeat_1160(shellcode_kernel, shellcode_kernel_len);
    printf("11.60 checkpoint: main: hv_defeat_1160 returned %d\n",
           hv_defeat_result);
    fflush(stdout);
    if (hv_defeat_result)
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
  } else if (fw == 0x1300 || fw == 0x1320 || fw == 0x1360) {
    if (hv_defeat_13xx(shellcode_kernel, shellcode_kernel_len))
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
#if FW_1160_PORT
  hold_1160_after_staging_failure("hv_defeat_1160");
#else
  return -1;
#endif
#endif
}
