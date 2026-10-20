#include "prepare_resume.h"
#if STAGE2A_1160
#include "../shellcode_kernel_1160/shellcode_kernel_1160.h"
#elif FW_1160_PORT
#include "../shellcode_kernel_port_1160/shellcode_kernel_port_1160.h"
#define shellcode_kernel_bin shellcode_kernel_port_1160_bin
#define shellcode_kernel_bin_len shellcode_kernel_port_1160_bin_len
#else
#include "../shellcode_kernel/shellcode_kernel.h"
#include "shellcode_1360.h"
#endif
#include "../shellcode_kernel/shellcode_kernel_args.h"
#include "../shellcode_kernel/shellcode_kernel_args_validate.h"
#include "config.h"
#include "iommu.h"
#include "offsets.h"
#include "utils.h"
#if PS5_1160_BOUNDED_BOOT_FILES
#include "loader_staging_1160.h"
#endif
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#if FW_1160_PORT
static void checkpoint_1160_resume(const char *stage) {
  if (fw != PS5_FW_1160)
    return;
  printf("11.60 checkpoint: prepare_resume: %s\n", stage);
  fflush(stdout);
}

static int page_chain_set_rw_checked_1160(uint64_t va) {
  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t index = (va >> shift) & 0x1ff;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + index * 8;
    uint64_t entry = 0;

    if (kernel_copyout(entry_va, &entry, sizeof(entry)) != 0 ||
        !PAGE_P(entry))
      return -1;

    uint64_t updated = entry;
    PAGE_SET_RW(updated);
    PAGE_CLEAR_XO(updated);
    if (updated != entry) {
      uint64_t observed = 0;
      if (kernel_copyin(&updated, entry_va, sizeof(updated)) != 0 ||
          kernel_copyout(entry_va, &observed, sizeof(observed)) != 0 ||
          observed != updated)
        return -1;
      entry = updated;
    }

    if (((level == 1 || level == 2) && PAGE_PS(entry)) || level == 3)
      return 0;
    table_phys = PAGE_PA(entry);
  }
  return -1;
}
#endif

#if !(STAGE2A_1160 || FW_1160_PORT)
static int apply_1360_dma_e820_map(void *buffer, size_t length) {
  static const struct {
    size_t offset;
    uint32_t expected;
    uint32_t replacement;
  } patches[] = {
      {0x1889, 0x3FEFC000, 0x00F00000},
      {0x18AC, 0x3FFFC000, 0x01000000},
      {0x18B7, 0x00004000, 0x3F000000},
  };
  uint8_t *code = buffer;

  for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); i++) {
    uint32_t value;
    if (patches[i].offset > length ||
        length - patches[i].offset < sizeof(value))
      return -1;
    memcpy(&value, code + patches[i].offset, sizeof(value));
    if (value != patches[i].expected)
      return -1;
  }

  for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); i++)
    memcpy(code + patches[i].offset, &patches[i].replacement,
           sizeof(patches[i].replacement));

  return 0;
}
#endif

#if STAGE2A_1160
static void stage2a_rollback_or_hold(page_install_transaction *transaction) {
  if (rollback_page_syscore(transaction) == 0)
    return;
  notify("11.60 Stage 2A: rollback readback failed; holding all backing. "
         "Cold reboot now.\n");
  while (1)
    sleep(30);
}

static int prepare_resume_1160_stage2a(void **shellcode_kernel,
                                      size_t *shellcode_kernel_len) {
  uint64_t args_va = prepare_sck_args();
  if (args_va == 0)
    return -1;

  *shellcode_kernel = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (*shellcode_kernel == MAP_FAILED)
    return -1;

  memset(*shellcode_kernel, 0, PAGE_SIZE);
  memcpy(*shellcode_kernel, shellcode_kernel_1160_bin,
         shellcode_kernel_1160_bin_len);
  *shellcode_kernel_len = shellcode_kernel_1160_bin_len;

  if (update_sck_args_ptr((uint64_t)*shellcode_kernel,
                          *shellcode_kernel_len, args_va))
    return -1;

  uint64_t base_pa = vtophys_user((uintptr_t)*shellcode_kernel);
  if (base_pa == 0 || (base_pa & 0x3fff) != 0) {
    notify("11.60 Stage 2A: wake backing is not 16-KiB aligned\n");
    return -1;
  }
  for (uint64_t i = 0x1000; i < PAGE_SIZE; i += 0x1000) {
    if (vtophys_user((uintptr_t)*shellcode_kernel + i) != base_pa + i) {
      notify("11.60 Stage 2A: wake backing is not physically contiguous\n");
      return -1;
    }
  }

  page_install_transaction transaction = {0};
  int install_result = install_page_rx_syscore(
      kernel_cave_shellcode, base_pa, 0, &transaction);
  if (install_result == -2) {
    notify("11.60 Stage 2A: install rollback failed; holding all backing. "
           "Cold reboot now.\n");
    while (1)
      sleep(30);
  }
  if (install_result != 0) {
    notify("11.60 Stage 2A: destination occupied or RX install failed\n");
    return -1;
  }
  if (verify_page_rx_syscore(kernel_cave_shellcode, base_pa)) {
    stage2a_rollback_or_hold(&transaction);
    notify("11.60 Stage 2A: RX alias verification failed\n");
    return -1;
  }

  uint8_t readback[sizeof(shellcode_kernel_1160_bin)];
  kread(pa_to_dmap(base_pa), readback, sizeof(readback));
  if (memcmp(readback, *shellcode_kernel, sizeof(readback)) != 0) {
    stage2a_rollback_or_hold(&transaction);
    notify("11.60 Stage 2A: wake byte readback failed\n");
    return -1;
  }

  notify("11.60 Stage 2A PASS: inert wake page staged RX at fixed alias; "
         "no hook/HV/rest/Linux action was taken\n");
  return 0;
}
#endif

int remove_xotext(void) {
#if FW_1160_PORT
  if (fw == PS5_FW_1160) {
    /*
     * The broad all-.text walk was the last operation observed before an
     * earlier 11.60 crash.  The hardware-tested 11.60 path only opens the two
     * mappings that this Sonic-style handoff must write: the CFI handler byte
     * patched by the wake shellcode and the executable cave populated by the
     * resume ROP.  Executing the remaining XOM text does not require making it
     * readable or writable.
     */
    if (env_offset.KERNEL_CFI_CHECK == 0 ||
        env_offset.KERNEL_CODE_CAVE == 0 || shellcode_kernel_bin_len == 0)
      return -1;

    if (page_chain_set_rw_checked_1160(ktext +
                                       env_offset.KERNEL_CFI_CHECK))
      return -1;
    for (size_t offset = 0; offset < shellcode_kernel_bin_len;
         offset += 0x1000) {
      if (page_chain_set_rw_checked_1160(
              ktext + env_offset.KERNEL_CODE_CAVE + offset))
        return -1;
    }

    printf("11.60 checkpoint: prepare_resume: selective CFI/wake-cave text "
           "permissions complete (%u wake bytes)\n",
           shellcode_kernel_bin_len);
    fflush(stdout);
    return 0;
  }
#endif

  uint64_t start = ktext;
  uint64_t end = kdata;
  int n __attribute__((unused)) = 0;

  for (uint64_t a = start; a < end; a += 0x1000) {
    page_chain_set_rw(a);
    n++;
  }
  return 0;
}

int kernel_pmap_invalidate_all(void) {
  static uint64_t two_zero_pages[PAGE_SIZE * 2] = {0};

  int pipe_fds[2];

  if (pipe2(pipe_fds, O_NONBLOCK)) {
    return -1;
  }

  if (write(pipe_fds[1], two_zero_pages, PAGE_SIZE * 2) < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return -1;
  }

  close(pipe_fds[1]);

  uint64_t read_fd_file_data = kernel_get_proc_file(-1, pipe_fds[0]);

  if (!INKERNEL(read_fd_file_data)) {
    close(pipe_fds[0]);
    return -1;
  }

  uint64_t read_fd_buffer;
  kernel_copyout(read_fd_file_data + 0x10, &read_fd_buffer,
                 sizeof(read_fd_buffer));

  if (!INKERNEL(read_fd_buffer)) {
    close(pipe_fds[0]);
    return -1;
  }

  if (!page_remove_global(read_fd_buffer)) {
    close(pipe_fds[0]);
    return -1;
  }

  close(pipe_fds[0]);
  return 0;
}

int prepare_resume(void **shellcode_kernel, size_t *shellcode_kernel_len) {
#if STAGE2A_1160
  if (fw != PS5_FW_1160)
    return -1;
  return prepare_resume_1160_stage2a(shellcode_kernel,
                                    shellcode_kernel_len);
#else
  if (env_offset.KERNEL_CODE_CAVE == 0) {
    printf("Error: missing code cave offset\n");
    return -1;
  }

  /* Build and validate the argument block before allocating or publishing. */
  uint64_t args_va = prepare_sck_args();
  if (args_va == 0)
    return -1;
#if FW_1160_PORT
  checkpoint_1160_resume("argument page prepared and read back");
#endif

  // Copy shellcode_kernel.
#if FW_1160_PORT
  checkpoint_1160_resume("wake user mapping begin");
  /*
   * The dedicated 11.60 build stages only its own wake blob.  Alias the
   * selection names to it so this path compiles exactly as in Run 15.
   */
#define shellcode_src shellcode_kernel_bin
#define shellcode_len shellcode_kernel_bin_len
#else
  const uint8_t *shellcode_src = shellcode_kernel_bin;
  size_t shellcode_len = shellcode_kernel_bin_len;
  if (fw == 0x1360) {
    shellcode_src = stock_shellcode_kernel_1360;
    shellcode_len = stock_shellcode_kernel_1360_len;
  }
#endif
  *shellcode_kernel =
      mmap(NULL, ALIGN_UP(shellcode_len, PAGE_SIZE),
           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (*shellcode_kernel == MAP_FAILED)
    return -1;
  *shellcode_kernel_len = shellcode_len;
  memcpy(*shellcode_kernel, shellcode_src, shellcode_len);
#if FW_1160_PORT
  checkpoint_1160_resume("wake user mapping populated");
#else
  if (fw == 0x1360 &&
      apply_1360_dma_e820_map(*shellcode_kernel, shellcode_len)) {
    notify("13.60 DMA E820 patch did not match stock shellcode\n");
    return -1;
  }
#endif

  if (update_sck_args_ptr((uint64_t)*shellcode_kernel,
                          shellcode_len, args_va))
    return -1;

  // Install shellcode_kernel in kernel space.
#if FW_1160_PORT
  checkpoint_1160_resume("wake alias install begin");
#endif
  for (size_t i = 0; i < shellcode_len; i += PAGE_SIZE) {
    install_page_syscore(kernel_cave_shellcode + i,
                         vtophys_user((uintptr_t)*shellcode_kernel + i), 0);
  }
#if FW_1160_PORT
  checkpoint_1160_resume("wake alias install complete");
#undef shellcode_src
#undef shellcode_len
#endif

#if FW_1160_PORT
  checkpoint_1160_resume("remove_xotext begin");
#endif
  if (remove_xotext()) {
    printf("Error: could not remove xo from text\n");
    return -1;
  }
#if FW_1160_PORT
  checkpoint_1160_resume("remove_xotext complete");
  checkpoint_1160_resume("pmap invalidation begin");
#endif

  if (kernel_pmap_invalidate_all()) {
    printf("Error: could not invalidate pmap\n");
    return -1;
  }
#if FW_1160_PORT
  checkpoint_1160_resume("pmap invalidation complete");
#endif

  return 0;
#endif
}

int update_sck_args_ptr(uint64_t shellcode, size_t shellcode_len,
                        uint64_t args) {
  // Find the address 0x11AA11AA11AA11AA used as marker
  size_t offset = 0;
  size_t matches = 0;
  if (shellcode_len < sizeof(uint64_t))
    return -1;
  for (size_t i = 0; i <= shellcode_len - sizeof(uint64_t); i++) {
    if (*(uint64_t *)(shellcode + i) == 0x11AA11AA11AA11AA) {
      offset = i;
      matches++;
    }
  }
  if (matches != 1) {
    notify("Expected exactly one args_ptr marker - Aborting\n");
    return -1;
  }
  *(uint64_t *)(shellcode + offset) = args;
  return 0;
}

uint64_t prepare_sck_args(void) {
  shellcode_kernel_args args = {0};
  args.fw_version = fw;
  args.ktext = ktext;
  args.kdata = kdata;
  args.dmap_base = dmap;

  /* A missing offset must remain NULL, never become ktext. */
#define KTEXT_OR_NULL(offset) ((offset) == 0 ? 0 : ktext + (offset))
  args.fun_printf = KTEXT_OR_NULL(env_offset.FUN_PRINTF);
  args.fun_hv_iommu_set_buffers =
      KTEXT_OR_NULL(env_offset.FUN_HV_IOMMU_SET_BUFFERS);
  args.fun_hv_iommu_wait_completion =
      KTEXT_OR_NULL(env_offset.FUN_HV_IOMM_WAIT_COMPLETION);
  args.fun_smp_rendezvous = KTEXT_OR_NULL(env_offset.FUN_SMP_RENDEZVOUS);
  args.fun_smp_no_rendevous_barrier =
      KTEXT_OR_NULL(env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER);
  args.g_vbios = KTEXT_OR_NULL(env_offset.G_VBIOS);

  args.fun_transmitter_control =
      KTEXT_OR_NULL(env_offset.FUN_TRANSMITTER_CONTROL);
  args.fun_mp3_initialize = KTEXT_OR_NULL(env_offset.FUN_MP3_INITIALIZE);
  args.fun_mp3_invoke = KTEXT_OR_NULL(env_offset.FUN_MP3_INVOKE);

  args.iommu_softc = KTEXT_OR_NULL(env_offset.IOMMU_SOFTC);

  args.kernel_uart_override =
      KTEXT_OR_NULL(env_offset.KERNEL_UART_OVERRIDE);
  args.kernel_cfi_check = KTEXT_OR_NULL(env_offset.KERNEL_CFI_CHECK);
#undef KTEXT_OR_NULL
  args.hv_handle_vmexit_pa = env_offset.HV_HANDLE_VMEXIT_PA;
  args.hv_code_cave_pa = env_offset.HV_CODE_CAVE_PA;

  args.linux_info_va = linux_i.linux_info;

  if (fw == PS5_FW_1160 && validate_shellcode_kernel_args_1160(&args) != 0) {
    notify("11.60 wake arguments failed preflight; no state was changed\n");
    return 0;
  }
#if FW_1160_PORT
  checkpoint_1160_resume("argument preflight passed");
#endif

#if PS5_1160_BOUNDED_BOOT_FILES
  /* The wake blob reads its arguments from this page.  Keep them out of the
   * page under the #SX stack page, which its stack reaches past 0x1040 bytes.
   * Pages taken here stay allocated, so each try gets a different page. */
  uint64_t args_pa = alloc_page();
  while (pa_under_sx_stack_1160(args_pa))
    args_pa = alloc_page();
  uint64_t args_cave = pa_to_dmap(args_pa);
#else
  uint64_t args_cave = pa_to_dmap(alloc_page());
#endif
  kernel_copyin(&args, args_cave, sizeof(args));

  if (fw == PS5_FW_1160) {
    shellcode_kernel_args readback = {0};
#if FW_1160_PORT
    checkpoint_1160_resume("argument readback begin");
#endif
    kernel_copyout(args_cave, &readback, sizeof(readback));
    if (memcmp(&args, &readback, sizeof(args)) != 0 ||
        validate_shellcode_kernel_args_1160(&readback) != 0) {
      notify("11.60 wake arguments failed exact readback\n");
      return 0;
    }
#if FW_1160_PORT
    checkpoint_1160_resume("argument readback passed");
#endif
  }

  return args_cave;
}
