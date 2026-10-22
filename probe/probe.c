/*
 * ps5-1160-probe: bounded USB data collection for retail firmware 11.60 on a
 * regular PS5 or a PS5 Pro. Send it to elfldr (port 9021) after the usual
 * kernel exploit. See README.md.
 *
 * The probe logic performs no loader, kernel-text or hypervisor patches and
 * never reads HV target data, MMIO or rest-mode state. The SDK runtime/KEX
 * initializes before main and patches this process's credentials/call-range
 * bounds; kernel_copyout also uses temporary exploit-pipe metadata writes.
 * Page tables are found only through SDK values (kernel_get_proc,
 * KERNEL_OFFSET_*, KERNEL_ADDRESS_*), which elfldr already depends on, so
 * this works on a kernel build that differs from the regular one. Every
 * kernel read requested by the probe logic is one of:
 *   - a few pointer reads that find this process's pmap and proc0's pmap,
 *   - a page-table entry read through the direct map,
 *   - a kernel data read inside [kdata, kdata + KDATA_LEN) whose 4-KiB frames
 *     all passed a page-table walk first: present, not execute-only at any
 *     level, write-back, mapped linearly with kdata (part of the loaded kernel
 *     image), and not in kernel text, an HV, MMIO, reserved or non-RAM
 *     physical range.
 * Reads at fixed regular-build offsets (FACS, IDT, TSS, DATA_CAVE, VBIOS, the
 * EFI slot) run only when the build anchors match.
 * check-readonly.sh fails the build if the sources or objects reach for
 * anything else.
 */

#include "hash.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/pciio.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

int sceKernelGetMainSocId(void);
int sceKernelGetCurrentCpu(void);
int sceKernelGetHwModelName(char *);
int sceKernelSendNotificationRequest(int, void *, size_t, int);

/* Set by the SDK runtime to pm_pml4 - pm_cr3 of this process's pmap. crt1.o
 * exports it; the v0.44 headers do not declare it. */
extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define PROBE_VERSION "3"
#define FW_1160_RAW 0x11600005U
#define PRO_SOC_ID 0x840fd0

#ifndef PROBE_MAP_ONLY
#define PROBE_MAP_ONLY 0
#endif

#if PROBE_MAP_ONLY
#define REPORT_BASE "ps5-1160-map-probe-report"
#else
#define REPORT_BASE "ps5-1160-probe-report"
#endif
#define DUMP_BASE "ps5-1160-kdata"
#ifndef USB_ROOT_FMT
#define USB_ROOT_FMT "/mnt/usb%d"
#endif
#define DEVKIT_LIB "/system/priv/lib/libSceDeci5Dtracep.sprx"
#define TESTKIT_LIB "/system/priv/lib/libSceDeci5Ttyp.sprx"

/* KERNBASE: kernel text of any build lies in [KERNBASE, kdata). The dump
 * window matches the regular-console reference dump (sha256 5705d4e9). */
#define KERNBASE 0xFFFFFFFF80000000UL
#define KTEXT_LEN 0xD30000UL
#define KDATA_LEN 0x5450000UL
#define BEYOND_LEN 0x1000000UL
#define TEXT_SCAN_MAX 0x4000000UL
#define FRAME 0x1000UL
#define PAGE16K 0x4000UL
#define WINDOW_LEN 0x10000UL
#define PROGRESS_STEP 0x400000UL
#define PA_LIMIT 0x1000000000UL
#define STDOUT_WAIT_MS 10000
#define MAP_MAX 256
#define DENY_MAX 640

/* Regular 11.60 offsets relative to ktext, as in source/offsets.c. Used only
 * when the anchors match, except the two anchors themselves. */
#define OFF_CODE_CAVE 0xD2B000UL
#define OFF_BUILD_STRING 0x10A1E94UL
#define OFF_IW620 0x1585D90UL
#define IW620_LEN 0x799BCUL
#define OFF_DATA_CAVE 0x2D02000UL
#define OFF_EFI_ROOT_SLOT 0x2D922D0UL
#define OFF_FACS 0x39CD1F0UL
#define OFF_IDT 0x3BA0300UL
#define OFF_COMMON_TSS 0x3BA2FE0UL
#define OFF_G_VBIOS 0x3DB7A40UL
#define VBIOS_LEN 0x10000UL
#define OFF_BOOT_METADATA 0x3E10000UL
#define OFF_IMAGE_SIZE_REC 0x3E10038UL
#define VMSPACE_VM_PMAP_1160 0x1D8 /* off_1160 pointer; compared, not used */
#define PMAP_PML4 0x20             /* pm_pml4 and pm_cr3, as the SDK reads */
#define TSS_STRIDE 0x68
#define NCPU 16

/* Expected values, all checked against the regular CFI-1115B dump. */
static const char BUILD_STRING[] =
    "W:/Build/J03675007/sys/freebsd/sys/fs/devpfs/devpfs_shadowtbl.c";
#define IMAGE_SIZE_REC 0x800000004UL /* MODINFO_SIZE header: type 4, len 8 */
#define IMAGE_SIZE_1160 0x3E0E040UL
#define IW620_SHA256                                                           \
  "eafef24af118f96f84a652e17aeed555ec4ac719b9fac11ff98a2de7e2b4b369"
#define VBIOS_SHA256_REGULAR                                                   \
  "229d76bb99e654057177f359f91ff279b55438b8eaf67ae3480f4b8d343e3954"
#define HV_R_REGULAR 0x62800000UL
#define HV_S_REGULAR 0x2029000UL
#define HV_VMCB_REGULAR_LO 0x200000UL
#define HV_VMCB_REGULAR_HI 0x1000000UL
#define HV_VMCB_PRO_LO 0xA00000UL
#define HV_VMCB_PRO_HI 0x1800000UL

#define PTE_P (1UL << 0)
#define PTE_RW (1UL << 1)
#define PTE_US (1UL << 2)
#define PTE_PWT (1UL << 3)
#define PTE_PCD (1UL << 4)
#define PTE_PS (1UL << 7)
#define PTE_PAT4K (1UL << 7)
#define PTE_G (1UL << 8)
#define PTE_PATBIG (1UL << 12)
#define PTE_XO (1UL << 58)
#define PTE_NX (1UL << 63)
#define PTE_ADDR 0x000FFFFFFFFFF000UL

/* ktext is the SDK's (kdata - 0xd30000 on 11.60); text_lo is measured. */
static uint64_t ktext, kdata, dmap, kcr3, kdata_pa, text_lo, own_vmspace;
static int edge_ok;

/* ---- output ---------------------------------------------------------- */

static int report_fd = -1, stdout_dead;
static char out_dir[192], suffix[8];

static int write_all(int fd, const void *buf, size_t len) {
  const uint8_t *p = buf;

  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

/* stdout is the elfldr socket. If the sender stops reading or goes away,
 * give up on it after one wait instead of stalling the dump. */
static void emit(int console, const char *fmt, va_list ap) {
  char line[1024];
  int n = vsnprintf(line, sizeof(line), fmt, ap);

  if (n <= 0)
    return;
  if ((size_t)n >= sizeof(line))
    n = sizeof(line) - 1;
  if (console && !stdout_dead) {
    struct pollfd p = {.fd = 1, .events = POLLOUT};
    if (poll(&p, 1, STDOUT_WAIT_MS) != 1 ||
        (p.revents & (POLLERR | POLLHUP | POLLNVAL)) ||
        write_all(1, line, (size_t)n))
      stdout_dead = 1;
  }
  if (report_fd >= 0)
    write_all(report_fd, line, (size_t)n);
}

/* To stdout and the report. */
__attribute__((format(printf, 1, 2))) static void out(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  emit(1, fmt, ap);
  va_end(ap);
}

/* To the report only, for long tables. */
__attribute__((format(printf, 1, 2))) static void rep(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  emit(0, fmt, ap);
  va_end(ap);
}

static void section(const char *title) {
  if (report_fd >= 0)
    fsync(report_fd);
  out("\n== %s\n", title);
}

/* Printable ASCII copy of at most len bytes, stopping at NUL. */
static const char *clean(char *dst, size_t cap, const void *src, size_t len) {
  const uint8_t *s = src;
  size_t j = 0;

  for (size_t i = 0; i < len && j + 1 < cap && s[i]; i++)
    dst[j++] = (s[i] >= 0x20 && s[i] < 0x7f) ? (char)s[i] : '?';
  dst[j] = 0;
  return dst;
}

static int exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

static void out_path(char *dst, size_t cap, const char *base, const char *ext) {
  snprintf(dst, cap, "%s/%s%s%s", out_dir, base, suffix, ext);
}

/* First free name set: no suffix, then -02 .. -99. Nothing is overwritten. */
static int pick_names(void) {
  char a[256], b[256], c[256];

  for (int n = 1; n < 100; n++) {
    if (n == 1)
      suffix[0] = 0;
    else
      snprintf(suffix, sizeof(suffix), "-%02d", n);
    out_path(a, sizeof(a), REPORT_BASE, ".txt");
    if (PROBE_MAP_ONLY) {
      if (!exists(a))
        return 0;
      continue;
    }
    out_path(b, sizeof(b), DUMP_BASE, ".bin");
    out_path(c, sizeof(c), DUMP_BASE, ".bin.part");
    if (!exists(a) && !exists(b) && !exists(c))
      return 0;
  }
  return -1;
}

/* A USB root counts only if a filesystem is mounted there, i.e. it sits on
 * a different mount than its parent directory. */
static int is_mount_point(const char *dir) {
  struct statfs sf, pf;
  char parent[192];

  snprintf(parent, sizeof(parent), "%s", dir);
  char *slash = strrchr(parent, '/');
  if (!slash || slash == parent)
    return 0;
  *slash = 0;
  if (statfs(dir, &sf) || statfs(parent, &pf))
    return 0;
  return strcmp(sf.f_mntonname, pf.f_mntonname) != 0;
}

static int try_dir(const char *dir, int need_mount) {
  struct stat st;
  struct statfs sf;
  char path[256];

  if (stat(dir, &st) || !S_ISDIR(st.st_mode) || statfs(dir, &sf))
    return -1;
  if (need_mount && !is_mount_point(dir))
    return -1;
  snprintf(out_dir, sizeof(out_dir), "%s", dir);
  if (pick_names())
    return -1;
  out_path(path, sizeof(path), REPORT_BASE, ".txt");
  report_fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  return report_fd >= 0 ? 0 : -1;
}

static int open_report(void) {
  char dir[192];

  for (int i = 0; i < 8; i++) {
    snprintf(dir, sizeof(dir), USB_ROOT_FMT, i);
    if (try_dir(dir, 1) == 0)
      return 0;
  }
  out_dir[0] = 0;
  return -1;
}

static void close_report(void) {
  if (report_fd >= 0) {
    fsync(report_fd);
    close(report_fd);
    report_fd = -1;
  }
}

static void notify(const char *msg) {
  struct {
    char pad[45];
    char msg[3075];
  } req;

  memset(&req, 0, sizeof(req));
  snprintf(req.msg, sizeof(req.msg), "%s", msg);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static int sysctl_get(const char *name, void *buf, size_t *len) {
  return sysctlbyname(name, buf, len, NULL, 0);
}

/* ---- checked kernel reads -------------------------------------------- */

enum {
  WK_OK,
  WK_ABSENT,
  WK_XO,
  WK_UNCACHED,
  WK_DENIED,
  WK_NOT_RAM,
  WK_NONLINEAR,
  WK_ERROR,
  WK_READ,
  WK_OUTSIDE,
  WK_COUNT,
};

static const char *const wname[WK_COUNT] = {
    "ok",       "not mapped", "execute-only",   "not write-back",
    "PA denied", "not RAM",   "not linear",     "walk error",
    "read error", "outside window",
};

struct walk {
  uint64_t e[4];
  int levels;
  int leaf;
  uint64_t size;
  uint64_t pa;
  int upper_xo;
};

struct range {
  uint64_t base;
  uint64_t size;
};

/* Physical ranges no read may touch: kernel text, HV candidates, MMIO and
 * reserved EFI ranges. Overlapping or touching ranges are merged. */
static struct range deny[DENY_MAX];
static int ndeny, deny_full;

/* RAM per map source (EFI types 1-4 and 7). Once a map is parsed, a frame
 * must be RAM in every parsed map that lists any RAM. */
enum { SRC_METADATA, SRC_SYSCTL };
static const char *const src_name[] = {"boot metadata", "machdep.efi_map"};
static struct range ram[2][MAP_MAX];
static int nram[2], have_map[2];

static void deny_add(uint64_t base, uint64_t size) {
  if (!size || base + size < base)
    return;
  for (int i = 0; i < ndeny; i++) {
    struct range *r = &deny[i];
    if (base <= r->base + r->size && base + size >= r->base) {
      uint64_t lo = MIN(base, r->base), hi = MAX(base + size, r->base + r->size);
      r->base = lo;
      r->size = hi - lo;
      return;
    }
  }
  if (ndeny < DENY_MAX)
    deny[ndeny++] = (struct range){base, size};
  else
    deny_full = 1;
}

static int pa_denied(uint64_t pa, uint64_t len) {
  for (int i = 0; i < ndeny; i++)
    if (pa < deny[i].base + deny[i].size && pa + len > deny[i].base)
      return 1;
  return 0;
}

static int pa_ram_ok(uint64_t pa, uint64_t len) {
  for (int src = 0; src < 2; src++) {
    int in = 0;
    if (!have_map[src] || !nram[src])
      continue;
    for (int i = 0; i < nram[src] && !in; i++)
      in = pa >= ram[src][i].base &&
           pa + len <= ram[src][i].base + ram[src][i].size;
    if (!in)
      return 0;
  }
  return 1;
}

static int is_kptr(uint64_t v) { return v >= 0xFFFF800000000000UL; }

/* Kernel text of any build: [KERNBASE, kdata). */
static int in_ktext(uint64_t va, uint64_t len) {
  uint64_t lo = MIN(KERNBASE, ktext);
  return va < kdata && va + len > lo;
}

/* Regular 11.60 offsets are ktext-relative; the window is anchored on kdata. */
static uint64_t kd(uint64_t ktext_off) { return kdata - KTEXT_LEN + ktext_off; }

static int read_pte(uint64_t pa, uint64_t *value) {
  *value = 0;
  if ((pa & 7) || pa >= PA_LIMIT || pa_denied(pa, 8) || !pa_ram_ok(pa, 8) ||
      in_ktext(dmap + pa, 8))
    return -1;
  return kernel_copyout((intptr_t)(dmap + pa), value, 8) == 0 ? 0 : -1;
}

static int walk_va(uint64_t va, struct walk *w) {
  uint64_t table = kcr3;

  memset(w, 0, sizeof(*w));
  w->leaf = -1;
  for (int level = 0; level < 4; level++) {
    uint64_t entry;
    uint64_t index = (va >> (39 - 9 * level)) & 0x1FF;

    if (read_pte((table & PTE_ADDR) + index * 8, &entry))
      return WK_ERROR;
    w->e[level] = entry;
    w->levels = level + 1;
    if (!(entry & PTE_P))
      return WK_ABSENT;
    if (level == 3 || ((level == 1 || level == 2) && (entry & PTE_PS))) {
      uint64_t size = level == 3 ? FRAME : level == 2 ? 1UL << 21 : 1UL << 30;
      uint64_t pat = level == 3 ? PTE_PAT4K : PTE_PATBIG;
      uint64_t frame;
      w->leaf = level;
      w->size = size;
      w->pa = (entry & PTE_ADDR & ~(size - 1)) | (va & (size - 1));
      frame = w->pa & ~(FRAME - 1);
      /* Execute-only anywhere on the chain may fault on a read. */
      if ((entry & PTE_XO) || w->upper_xo)
        return WK_XO;
      /* Write-back only: PAT index 0. Device mappings use other types. */
      if (entry & (PTE_PWT | PTE_PCD | pat))
        return WK_UNCACHED;
      if (frame >= PA_LIMIT || pa_denied(frame, FRAME))
        return WK_DENIED;
      if (!pa_ram_ok(frame, FRAME))
        return WK_NOT_RAM;
      return WK_OK;
    }
    if (entry & PTE_XO)
      w->upper_xo = 1;
    table = entry;
  }
  return WK_ERROR;
}

/* Each frame must walk clean and map at kdata_pa + (va - kdata): the kernel
 * image is mapped linearly, later dynamic mappings are not. */
static int check_range(uint64_t va, uint64_t len) {
  for (uint64_t f = va & ~(FRAME - 1); f < va + len; f += FRAME) {
    struct walk w;
    int rc = walk_va(f, &w);
    if (rc != WK_OK)
      return rc;
    if (w.pa != kdata_pa + (f - kdata))
      return WK_NONLINEAR;
  }
  return WK_OK;
}

/* The only way this probe reads kernel data. */
static int kread_data(uint64_t va, void *buf, uint64_t len) {
  memset(buf, 0, len);
  if (!kdata_pa || len == 0 || va + len < va || va < kdata ||
      va + len > kdata + KDATA_LEN || in_ktext(va, len))
    return WK_OUTSIDE;
  int rc = check_range(va, len);
  if (rc != WK_OK)
    return rc;
  if (kernel_copyout((intptr_t)va, buf, len)) {
    memset(buf, 0, len);
    return WK_READ;
  }
  return WK_OK;
}

static int kread_q(uint64_t va, uint64_t *value) {
  return kread_data(va, value, sizeof(*value));
}

static int kdata_sha256(uint64_t va, uint64_t len, char hex[65]) {
  static uint8_t buf[PAGE16K];
  uint8_t digest[32];
  sha256_ctx ctx;

  sha256_init(&ctx);
  for (uint64_t done = 0; done < len;) {
    uint64_t n = len - done < sizeof(buf) ? len - done : sizeof(buf);
    int rc = kread_data(va + done, buf, n);
    if (rc != WK_OK)
      return rc;
    sha256_update(&ctx, buf, n);
    done += n;
  }
  sha256_final(&ctx, digest);
  sha256_hex(digest, hex);
  return WK_OK;
}

/* Bootstrap reads of proc and vmspace fields, before the page tables are
 * known. Same fields and offsets the SDK runtime reads at startup. */
static int kread_boot(uint64_t va, void *buf, size_t len) {
  memset(buf, 0, len);
  if (!is_kptr(va) || (va & 3) || in_ktext(va, len))
    return -1;
  return kernel_copyout((intptr_t)va, buf, len) == 0 ? 0 : -1;
}

static void print_walk(const char *label, uint64_t va) {
  struct walk w;
  int rc = walk_va(va, &w);

  out("  %-24s %#018lx  %-14s", label, va, wname[rc]);
  if (w.leaf >= 0) {
    uint64_t e = w.e[w.leaf];
    uint64_t pat = w.leaf == 3 ? PTE_PAT4K : PTE_PATBIG;
    out(" L%d pa 0x%09lx%s%s%s%s%s%s%s%s%s%s", w.leaf, w.pa,
        (e & PTE_RW) ? " RW" : " RO", (e & PTE_US) ? " US" : "",
        (e & PTE_PWT) ? " PWT" : "", (e & PTE_PCD) ? " PCD" : "",
        (e & pat) ? " PAT" : "", w.leaf < 3 ? " PS" : "",
        (e & PTE_G) ? " G" : "", (e & PTE_XO) ? " XO" : "",
        (e & PTE_NX) ? " NX" : "", w.upper_xo ? " upper-XO" : "");
  }
  out("\n");
  rep("    entries:");
  for (int i = 0; i < w.levels; i++)
    rep(" %016lx", w.e[i]);
  rep("\n");
}

/* ---- identity --------------------------------------------------------- */

static int soc_id;
static char model[64];

static void sysctl_line(const char *name) {
  char buf[512], txt[256];
  size_t len = sizeof(buf) - 1;

  memset(buf, 0, sizeof(buf));
  if (sysctl_get(name, buf, &len)) {
    out("  %-18s unavailable (errno %d)\n", name, errno);
    return;
  }
  char *nl = strchr(buf, '\n');
  if (nl)
    *nl = 0;
  out("  %-18s %s\n", name, clean(txt, sizeof(txt), buf, len));
}

static void sysctl_number(const char *name) {
  uint64_t v = 0;
  size_t len = sizeof(v);

  if (sysctl_get(name, &v, &len)) {
    out("  %-18s unavailable (errno %d)\n", name, errno);
    return;
  }
  if (len == 4)
    v = (uint32_t)v;
  out("  %-18s %#lx (%lu)\n", name, v, v);
}

static void identity(uint32_t raw_fw) {
  char buf[1024];

  section("Identity");
  out("  firmware raw       %#010x (need %#010x)\n", raw_fw, FW_1160_RAW);
  soc_id = sceKernelGetMainSocId();
  out("  SoC ID             %#x (%s)\n", soc_id,
      soc_id == PRO_SOC_ID ? "PS5 Pro" : "not the Pro ID 0x840fd0");
  memset(buf, 0, sizeof(buf));
  if (sceKernelGetHwModelName(buf) == 0)
    clean(model, sizeof(model), buf, sizeof(buf));
  else
    snprintf(model, sizeof(model), "unavailable");
  out("  model name         %s\n", model);
  out("  devkit lib         %s\n", exists(DEVKIT_LIB) ? "present" : "absent");
  out("  testkit lib        %s\n", exists(TESTKIT_LIB) ? "present" : "absent");
  out("  kit type           %s\n",
      soc_id == PRO_SOC_ID       ? "retail Pro (loader rule: SoC ID first)"
      : exists(DEVKIT_LIB)       ? "devkit"
      : exists(TESTKIT_LIB)      ? "testkit"
                                 : "retail");
  sysctl_line("hw.model");
  sysctl_line("hw.machine");
  sysctl_number("hw.ncpu");
  sysctl_number("hw.physmem");
  sysctl_number("hw.realmem");
  sysctl_line("kern.ostype");
  sysctl_line("kern.osrelease");
  sysctl_line("kern.version");
  out("  SDK ktext          %#018lx\n", ktext);
  out("  SDK kdata          %#018lx (SDK assumes kdata - ktext = %#lx)\n",
      kdata, kdata - ktext);
  out("  SDK offsets        p_vmspace %#lx, p_pid %#lx, vmspace pmap %#lx\n",
      (uint64_t)KERNEL_OFFSET_PROC_P_VMSPACE,
      (uint64_t)KERNEL_OFFSET_PROC_P_PID,
      (uint64_t)KERNEL_OFFSET_VMSPACE_VM_PMAP);
}

/* ---- page tables ------------------------------------------------------- */

/* pm_pml4 and pm_cr3 of the pmap embedded in a vmspace, read the way the
 * SDK computes KERNEL_ADDRESS_DMAP_BASE. */
static int vmspace_pmap(uint64_t vmspace, uint64_t *pml4, uint64_t *cr3) {
  uint64_t pp[2];

  if (!is_kptr(vmspace) || (vmspace & 7) ||
      kread_boot(vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP + PMAP_PML4, pp,
                 sizeof(pp)))
    return -1;
  if (!is_kptr(pp[0]) || (pp[0] & (FRAME - 1)) || !pp[1] ||
      (pp[1] & (FRAME - 1)) || pp[1] >= PA_LIMIT || pp[0] <= pp[1])
    return -1;
  *pml4 = pp[0];
  *cr3 = pp[1];
  return 0;
}

/* proc0 is the last entry on allproc. Same list walk as kernel_get_proc. */
static uint64_t find_proc0(int *steps) {
  uint64_t p = 0;

  *steps = 0;
  if (kread_boot((uint64_t)KERNEL_ADDRESS_ALLPROC, &p, 8))
    return 0;
  for (int i = 0; i < 4096 && is_kptr(p) && !(p & 7); i++) {
    uint32_t pid;
    *steps = i + 1;
    if (kread_boot(p + KERNEL_OFFSET_PROC_P_PID, &pid, 4))
      return 0;
    if (pid == 0)
      return p;
    if (kread_boot(p, &p, 8))
      return 0;
  }
  return 0;
}

static int setup_paging(void) {
  uint64_t proc, vmspace = 0, pml4 = 0, cr3 = 0, sdk = KERNEL_ADDRESS_DMAP_BASE;
  struct walk w;
  int rc, steps;

  section("Page tables (this process's pmap, kernel half shared; SDK values "
          "only)");
  proc = (uint64_t)kernel_get_proc(getpid());
  if (!is_kptr(proc) || (proc & 7) ||
      kread_boot(proc + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace, 8) ||
      vmspace_pmap(vmspace, &pml4, &cr3)) {
    out("  cannot read this process's pmap\n");
    return -1;
  }
  dmap = pml4 - cr3;
  kcr3 = cr3;
  own_vmspace = vmspace;
  out("  vmspace %#lx: pm_pml4 %#lx pm_cr3 %#lx\n", vmspace, pml4, cr3);
  out("  dmap %#lx, SDK KERNEL_ADDRESS_DMAP_BASE %#lx: %s\n", dmap, sdk,
      dmap == sdk ? "same" : "DIFFERENT");
  if (dmap != sdk || !is_kptr(dmap) || in_ktext(pml4, 8))
    return -1;

  rc = walk_va(dmap + kcr3, &w);
  out("  self-check: dmap+cr3 maps to %#lx (%s, L%d)\n", w.pa, wname[rc],
      w.leaf);
  if (rc != WK_OK || w.pa != kcr3 || (dmap & (w.size - 1)))
    return -1;
  out("  dmap is %s aligned\n",
      (dmap & ((1UL << 30) - 1)) == 0 ? "1-GiB" : "leaf-size but not 1-GiB");

  uint64_t p0 = find_proc0(&steps), vs0 = 0, pml40, cr30;
  if (!p0) {
    out("  proc0: not found on allproc after %d entries, cross-check skipped\n",
        steps);
  } else if (kread_boot(p0 + KERNEL_OFFSET_PROC_P_VMSPACE, &vs0, 8) ||
             vmspace_pmap(vs0, &pml40, &cr30)) {
    out("  proc0 %#lx: pmap unreadable, cross-check skipped\n", p0);
  } else {
    out("  proc0 %#lx (allproc entry %d): kernel cr3 %#lx, dmap %#lx: %s\n", p0,
        steps, cr30, pml40 - cr30, pml40 - cr30 == dmap ? "same" : "DIFFERENT");
    if (pml40 - cr30 != dmap)
      return -1;
  }
  return 0;
}

/* Walk down from kdata while frames are execute-only: that is kernel text on
 * any build. Its physical frames go on the deny list. Page tables only. */
static int text_extent(int *linear) {
  uint64_t va = kdata - FRAME;
  int leaves = 0;

  text_lo = kdata;
  *linear = 1;
  while (va >= KERNBASE && kdata - va <= TEXT_SCAN_MAX) {
    struct walk w;
    if (walk_va(va, &w) != WK_XO)
      break;
    uint64_t base = va & ~(w.size - 1);
    deny_add(w.pa & ~(w.size - 1), w.size);
    if (w.pa != kdata_pa - (kdata - va))
      *linear = 0;
    text_lo = base;
    leaves++;
    va = base - FRAME;
  }
  return leaves;
}

static int kernel_layout(void) {
  struct walk t, d, m;
  int linear, leaves, rt, rd, rm;

  section("Kernel layout (page walks only, nothing read)");
  rt = walk_va(kdata - FRAME, &t);
  rd = walk_va(kdata, &d);
  out("  kdata-0x1000 %s; kdata %s, pa %#lx%s\n", wname[rt], wname[rd], d.pa,
      rd == WK_OK && !(d.e[d.leaf] & PTE_NX) ? ", no NX" : "");
  if (rd != WK_OK || !(d.e[d.leaf] & PTE_NX) || (d.pa & (FRAME - 1))) {
    out("  kdata base is not a mapped, write-back, no-execute data page\n");
    return -1;
  }
  /* Reported only: every read stays walk-checked and linear either way. */
  if (rt != WK_XO && rt != WK_ABSENT)
    out("  note: the frame below kdata is not execute-only; kdata may not be "
        "the first data page of this build\n");
  edge_ok = rt == WK_XO || rt == WK_ABSENT;
  kdata_pa = d.pa;

  rm = walk_va(dmap + kdata_pa, &m);
  out("  dmap check: dmap+pa(kdata) %s", wname[rm]);
  if (rm == WK_OK || m.leaf >= 0)
    out(", maps to %#lx", m.pa);
  out("\n");
  if (m.leaf >= 0 && m.pa != kdata_pa) {
    out("  direct map does not map pa(kdata) to itself\n");
    return -1;
  }

  leaves = text_extent(&linear);
  out("  execute-only below kdata: %#lx..kdata, %#lx bytes in %d leaf "
      "page(s), %s with kdata\n",
      text_lo, kdata - text_lo, leaves, linear ? "linear" : "NOT linear");
  out("  SDK ktext %#lx is %s that range\n", ktext,
      ktext == text_lo                     ? "the start of"
      : ktext > text_lo && ktext < kdata ? "inside"
                                           : "outside");
  return 0;
}

/* ---- EFI memory map ---------------------------------------------------- */

static struct range cands[2][16];
static int ncands[2];

static const char *efi_type(uint32_t t) {
  static const char *const names[] = {
      "Reserved", "LoaderCode", "LoaderData", "BSCode",   "BSData",
      "RTCode",   "RTData",     "Conventional", "Unusable", "ACPIReclaim",
      "ACPINVS",  "MMIO",       "MMIOPort",   "PalCode",  "Persistent",
  };
  return t < sizeof(names) / sizeof(names[0]) ? names[t] : "other";
}

/* buf holds struct efi_map_header followed by the descriptors at +0x20, the
 * same layout derive_h() walks in source/hv_defeat_13xx.c. */
static void parse_efi_map(const uint8_t *buf, size_t len, int src) {
  uint64_t map_size, desc_size;
  uint32_t version;

  if (have_map[src] || len < 0x20) {
    out("  %s: %zu bytes, %s\n", src_name[src], len,
        have_map[src] ? "map already parsed" : "too short for a map header");
    return;
  }
  memcpy(&map_size, buf, 8);
  memcpy(&desc_size, buf + 8, 8);
  memcpy(&version, buf + 16, 4);
  if (desc_size < 0x28 || desc_size > 0x80 || !map_size ||
      map_size > len - 0x20) {
    out("  %s: map %#lx bytes, descriptor %#lx: header out of range, not "
        "parsed\n",
        src_name[src], map_size, desc_size);
    return;
  }
  uint64_t count = map_size / desc_size, shown = MIN(count, MAP_MAX);
  rep("  %s: map %#lx bytes, descriptor %#lx bytes, version %u\n",
      src_name[src], map_size, desc_size, version);
  for (uint64_t i = 0; i < shown; i++) {
    const uint8_t *d = buf + 0x20 + i * desc_size;
    uint32_t type;
    uint64_t pa, pages, attr, size;
    memcpy(&type, d, 4);
    memcpy(&pa, d + 8, 8);
    memcpy(&pages, d + 0x18, 8);
    memcpy(&attr, d + 0x20, 8);
    size = pages <= (UINT64_MAX >> 12) ? pages << 12 : 0;
    if (pa + size < pa)
      size = 0;
    /* derive_h(): type 0, 24..64 MiB, nonzero base below 64 GiB. */
    int cand = type == 0 && pa && pa < PA_LIMIT && size > 0x17FFFFF &&
               size < 0x4000001;
    if (type == 0 || type == 11 || type == 12)
      deny_add(pa, size);
    if ((type >= 1 && type <= 4) || type == 7) {
      if (nram[src] < MAP_MAX)
        ram[src][nram[src]++] = (struct range){pa, size};
    }
    if (cand && ncands[src] < 16)
      cands[src][ncands[src]++] = (struct range){pa, size};
    rep("   %3lu %-12s pa 0x%09lx-0x%09lx size 0x%09lx attr %#lx%s\n", i,
        efi_type(type), pa, pa + size, size, attr,
        cand ? "  <- HV candidate" : "");
  }
  have_map[src] = 1;
  out("  %s: %lu entries (table in the report), %d RAM range(s), %d HV "
      "candidate(s)\n",
      src_name[src], count, nram[src], ncands[src]);
  if (count > MAP_MAX) {
    out("  %s: map truncated at %d entries\n", src_name[src], MAP_MAX);
    deny_full = 1;
  }
  if (!nram[src])
    out("  %s: no RAM ranges, not used for RAM checks\n", src_name[src]);
}

static void memory_sysctls(void) {
  static uint8_t buf[0x10000];
  size_t len;

  section("Memory map sysctls (no kernel reads)");
  len = sizeof(buf);
  if (sysctl_get("machdep.efi_map", buf, &len) == 0)
    parse_efi_map(buf, len, SRC_SYSCTL);
  else
    out("  machdep.efi_map    unavailable (errno %d)\n", errno);
  for (int i = 0; i < ncands[SRC_SYSCTL]; i++)
    deny_add(cands[SRC_SYSCTL][i].base, cands[SRC_SYSCTL][i].size);

  /* struct bios_smap_xattr: base, length, type, xattr. */
  len = sizeof(buf);
  if (sysctl_get("machdep.smap", buf, &len) == 0) {
    out("  machdep.smap       %zu entries (table in the report)\n", len / 24);
    for (size_t off = 0; off + 24 <= len && off < 24 * 64; off += 24) {
      uint64_t base, size;
      uint32_t type, xattr;
      memcpy(&base, buf + off, 8);
      memcpy(&size, buf + off + 8, 8);
      memcpy(&type, buf + off + 16, 4);
      memcpy(&xattr, buf + off + 20, 4);
      rep("   0x%09lx-0x%09lx type %u xattr %#x\n", base, base + size, type,
          xattr);
    }
  } else {
    out("  machdep.smap       unavailable (errno %d)\n", errno);
  }
  sysctl_number("machdep.acpi_root");

  len = sizeof(buf) - 1;
  memset(buf, 0, sizeof(buf));
  if (sysctl_get("vm.phys_segs", buf, &len) == 0) {
    char txt[160];
    char *line = (char *)buf;
    int lines = 0;
    while (line && *line && lines < 200) {
      char *nl = strchr(line, '\n');
      if (nl)
        *nl = 0;
      if (*line)
        rep("   %s\n", clean(txt, sizeof(txt), line, strlen(line)));
      line = nl ? nl + 1 : NULL;
      lines++;
    }
    out("  vm.phys_segs       %d line(s) (in the report)\n", lines);
  } else {
    out("  vm.phys_segs       unavailable (errno %d)\n", errno);
  }
}

/* ---- boot metadata ----------------------------------------------------- */

static uint64_t meta_va, mod_addr, mod_size;

/* MODINFO_NAME "kernel", then a MODINFO_TYPE record. The loader puts the
 * metadata on a page boundary, so only page starts are checked. */
static uint64_t find_metadata(int *checked) {
  static const uint8_t sig[] = {1, 0, 0, 0, 7, 0, 0, 0,
                                'k', 'e', 'r', 'n', 'e', 'l', 0};
  uint8_t b[0x18];

  *checked = 0;
  for (uint64_t off = 0; off + FRAME <= KDATA_LEN; off += FRAME) {
    uint32_t t2, s2;
    if (kread_data(kdata + off, b, sizeof(b)) != WK_OK)
      continue;
    (*checked)++;
    memcpy(&t2, b + 0x10, 4);
    memcpy(&s2, b + 0x14, 4);
    if (!memcmp(b, sig, sizeof(sig)) && t2 == 2 && s2 && s2 <= 32)
      return kdata + off;
  }
  return 0;
}

static void boot_metadata(int gate) {
  static uint8_t body[0x10000];
  uint64_t end = kdata + KDATA_LEN, rec;
  char txt[80];
  int checked;

  section("Boot metadata (found by signature, bounded walk, kernel data only)");
  rec = meta_va = find_metadata(&checked);
  if (!rec) {
    out("  not found in %d readable page start(s) of the window\n", checked);
    return;
  }
  out("  found at kdata+%#lx (%d page start(s) checked); regular 11.60 "
      "keeps it at kdata+%#lx: %s\n",
      rec - kdata, checked, OFF_BOOT_METADATA - KTEXT_LEN,
      rec == kd(OFF_BOOT_METADATA) ? "same" : "different");
  if (gate && rec != kd(OFF_BOOT_METADATA))
    out("  note: anchors match but the metadata moved\n");
  for (int i = 0; i < 64; i++) {
    uint32_t hdr[2];
    int rc = rec + 8 <= end ? kread_data(rec, hdr, 8) : WK_OUTSIDE;
    if (rc != WK_OK) {
      out("  record %d at kdata+%#lx: %s, stop\n", i, rec - kdata, wname[rc]);
      return;
    }
    uint32_t type = hdr[0], size = hdr[1];
    if (!type && !size) {
      out("  end of metadata after %d records\n", i);
      return;
    }
    if (size > sizeof(body) || rec + 8 + size > end) {
      out("  record %d: size %#x out of range, stop\n", i, size);
      return;
    }
    if (size) {
      rc = kread_data(rec + 8, body, size);
      if (rc != WK_OK) {
        out("  record %d body: %s, stop\n", i, wname[rc]);
        return;
      }
    }
    uint64_t v = 0;
    if (size == 8)
      memcpy(&v, body, 8);
    rep("  [%2d] kdata+%#lx type %#06x size %#x", i, rec - kdata, type, size);
    if (type == 1 || type == 2) {
      rep("  \"%s\"\n", clean(txt, sizeof(txt), body, size));
    } else if (type == 0x9004) {
      rep("  EFI memory map\n");
      parse_efi_map(body, size, SRC_METADATA);
    } else if (size == 8) {
      rep("  %#lx\n", v);
    } else {
      rep("\n");
    }
    if (type == 3 && size == 8)
      mod_addr = v;
    if (type == 4 && size == 8)
      mod_size = v;
    rec += 8 + (((uint64_t)size + 7) & ~7UL);
  }
  out("  stopped after 64 records\n");
}

static void image_summary(void) {
  if (!meta_va)
    return;
  out("  MODINFO_ADDR %#lx: %s SDK ktext, %s the execute-only start\n",
      mod_addr, mod_addr == ktext ? "equals" : "DIFFERS from",
      mod_addr == text_lo ? "equals" : "differs from");
  if (mod_addr && mod_size && mod_addr + mod_size > kdata &&
      mod_addr + mod_size <= kdata + KDATA_LEN)
    out("  MODINFO_SIZE %#lx: image ends at kdata+%#lx; the window runs "
        "%#lx bytes past it (metadata, boot page tables)\n",
        mod_size, mod_addr + mod_size - kdata,
        kdata + KDATA_LEN - (mod_addr + mod_size));
  else
    out("  MODINFO_SIZE %#lx\n", mod_size);
}

static void hv_candidates(void) {
  section("HV region candidates (type 0, 24-64 MiB, below 64 GiB)");
  for (int src = 0; src < 2; src++) {
    if (!have_map[src]) {
      out("  %-16s no map\n", src_name[src]);
      continue;
    }
    out("  %-16s %d candidate(s)\n", src_name[src], ncands[src]);
    for (int i = 0; i < ncands[src]; i++)
      out("    R 0x%09lx  S 0x%07lx  end 0x%09lx%s\n", cands[src][i].base,
          cands[src][i].size, cands[src][i].base + cands[src][i].size,
          i == 0 ? "  (derive_h takes the first)" : "");
  }
  if (have_map[0] && have_map[1] && ncands[0] && ncands[1])
    out("  sources agree on the first candidate: %s\n",
        cands[0][0].base == cands[1][0].base &&
                cands[0][0].size == cands[1][0].size
            ? "yes"
            : "NO");
  out("  regular 11.60 reference: R %#lx S %#lx\n", HV_R_REGULAR,
      HV_S_REGULAR);
  if (!have_map[0] && !have_map[1])
    out("  no EFI map from either source: PA deny list holds kernel text "
        "only; reads still need linear, write-back frames\n");
  out("  PA deny list: %d range(s)%s\n", ndeny, deny_full ? ", OVERFLOW" : "");
}

/* Map coverage of the HV candidate, without reading any byte in the region.
 * walk_va() reads page-table entries only. A mapped HV leaf normally returns
 * WK_DENIED because parse_efi_map() deliberately put the target PA on the
 * deny list; leaf >= 0 still gives us the mapping and its physical address. */
struct hv_map_state {
  int mapped;
  int identity;
  int scan_safe;
  int leaf;
  int upper_xo;
  uint64_t size;
  uint64_t flags;
};

static struct hv_map_state hv_map_state(uint64_t pa) {
  struct walk w;
  struct hv_map_state s = {0};

  int rc = walk_va(dmap + pa, &w);
  if (w.leaf < 0)
    return s;
  s.mapped = 1;
  s.identity = (w.pa & ~(FRAME - 1)) == pa;
  /* The target frame is deliberately on the PA deny list. Reaching
   * WK_DENIED therefore proves that every earlier read-safety check passed:
   * present, non-XO and write-back. No byte from the target was read. */
  s.scan_safe = rc == WK_DENIED;
  s.leaf = w.leaf;
  s.upper_xo = w.upper_xo;
  s.size = w.size;
  s.flags = w.e[w.leaf] &
            (PTE_RW | PTE_US | PTE_PWT | PTE_PCD | PTE_PAT4K | PTE_G |
             PTE_PATBIG | PTE_XO | PTE_NX);
  return s;
}

static int same_hv_map_state(const struct hv_map_state *a,
                             const struct hv_map_state *b) {
  return a->mapped == b->mapped && a->identity == b->identity &&
         a->scan_safe == b->scan_safe && a->leaf == b->leaf &&
         a->upper_xo == b->upper_xo &&
         a->size == b->size && a->flags == b->flags;
}

static void print_hv_map_run(uint64_t start, uint64_t end,
                             const struct hv_map_state *s) {
  if (!s->mapped) {
    out("    R+%#09lx..R+%#09lx  not mapped\n", start, end);
    return;
  }
  out("    R+%#09lx..R+%#09lx  mapped %s %s L%d/%#lx%s%s%s%s%s%s%s\n",
      start, end, s->identity ? "identity" : "ALIAS",
      s->scan_safe ? "scan-safe" : "NOT-SAFE", s->leaf, s->size,
      (s->flags & PTE_RW) ? " RW" : " RO",
      (s->flags & PTE_US) ? " US" : "",
      (s->flags & PTE_PWT) ? " PWT" : "",
      (s->flags & PTE_PCD) ? " PCD" : "",
      ((s->leaf == 3 && (s->flags & PTE_PAT4K)) ||
       (s->leaf < 3 && (s->flags & PTE_PATBIG)))
          ? " PAT"
          : "",
      (s->flags & PTE_XO) || s->upper_xo ? " XO" : "",
      (s->flags & PTE_NX) ? " NX" : "");
}

static void hv_mapping_coverage(void) {
  struct range hv = {0};
  uint64_t mapped = 0, identity = 0;
  uint64_t scan_safe = 0;
  uint64_t regular_mapped = 0, regular_identity = 0, regular_safe = 0;
  uint64_t pro_mapped = 0, pro_identity = 0, pro_safe = 0;
  int src = -1;

  if (ncands[SRC_METADATA]) {
    hv = cands[SRC_METADATA][0];
    src = SRC_METADATA;
  } else if (ncands[SRC_SYSCTL]) {
    hv = cands[SRC_SYSCTL][0];
    src = SRC_SYSCTL;
  }

  section("HV direct-map coverage (page-table entries only, HV not read)");
  if (src < 0 || !hv.size || (hv.base & (FRAME - 1)) ||
      (hv.size & (FRAME - 1))) {
    out("  no page-aligned HV candidate to walk\n");
    return;
  }

  out("  using %s first candidate: R %#lx S %#lx (%lu frames)\n",
      src_name[src], hv.base, hv.size, hv.size / FRAME);
  struct hv_map_state run = hv_map_state(hv.base);
  uint64_t run_start = 0;
  for (uint64_t off = 0; off < hv.size; off += FRAME) {
    struct hv_map_state cur = hv_map_state(hv.base + off);
    if (off && !same_hv_map_state(&run, &cur)) {
      print_hv_map_run(run_start, off, &run);
      run = cur;
      run_start = off;
    }
    mapped += cur.mapped;
    identity += cur.mapped && cur.identity;
    scan_safe += cur.mapped && cur.identity && cur.scan_safe;
    if (off >= HV_VMCB_REGULAR_LO && off < HV_VMCB_REGULAR_HI) {
      regular_mapped += cur.mapped;
      regular_identity += cur.mapped && cur.identity;
      regular_safe += cur.mapped && cur.identity && cur.scan_safe;
    }
    if (off >= HV_VMCB_PRO_LO && off < HV_VMCB_PRO_HI) {
      pro_mapped += cur.mapped;
      pro_identity += cur.mapped && cur.identity;
      pro_safe += cur.mapped && cur.identity && cur.scan_safe;
    }
  }
  print_hv_map_run(run_start, hv.size, &run);

  const uint64_t total = hv.size / FRAME;
  const uint64_t regular_total =
      (HV_VMCB_REGULAR_HI - HV_VMCB_REGULAR_LO) / FRAME;
  const uint64_t pro_total = (HV_VMCB_PRO_HI - HV_VMCB_PRO_LO) / FRAME;
  out("  full region: %lu/%lu mapped, %lu/%lu identity, %lu/%lu "
      "scan-safe\n",
      mapped, total, identity, total, scan_safe, total);
  out("  regular VMCB hypothesis R+%#lx..R+%#lx: %lu/%lu mapped, "
      "%lu/%lu identity, %lu/%lu scan-safe%s\n",
      HV_VMCB_REGULAR_LO, HV_VMCB_REGULAR_HI, regular_mapped, regular_total,
      regular_identity, regular_total, regular_safe, regular_total,
      regular_mapped == regular_total && regular_identity == regular_total &&
              regular_safe == regular_total
          ? "  PASS"
          : "  NOT SAFE TO SCAN");
  out("  Pro VMCB hypothesis     R+%#lx..R+%#lx: %lu/%lu mapped, "
      "%lu/%lu identity, %lu/%lu scan-safe%s\n",
      HV_VMCB_PRO_LO, HV_VMCB_PRO_HI, pro_mapped, pro_total, pro_identity,
      pro_total, pro_safe, pro_total,
      pro_mapped == pro_total && pro_identity == pro_total &&
              pro_safe == pro_total
                     ? "  PASS"
                     : "  NOT SAFE TO SCAN");
}

/* ---- anchors ----------------------------------------------------------- */

static int a_build, a_image, a_facs = -1, a_iw620 = -1;
static uint64_t efi_slot;

static const char *mm(int ok) {
  return ok < 0 ? "not read" : ok ? "MATCH" : "MISMATCH";
}

static void gate_anchors(void) {
  uint8_t b[sizeof(BUILD_STRING)];
  uint64_t v = 0, next = 0;
  char txt[80];
  int rc;

  section("Identity anchors (kernel data, each frame walked first)");
  rc = kread_data(kd(OFF_BUILD_STRING), b, sizeof(b));
  a_build = rc == WK_OK && memcmp(b, BUILD_STRING, sizeof(b)) == 0;
  out("  build string ktext+%#lx  %s  ", OFF_BUILD_STRING, mm(a_build));
  if (rc != WK_OK)
    out("(%s)\n", wname[rc]);
  else if (a_build || memcmp(b, "W:/Build/", 9) == 0)
    out("\"%s\"\n", clean(txt, sizeof(txt), b, sizeof(b)));
  else
    out("(no build path at this offset)\n");

  rc = kread_q(kd(OFF_IMAGE_SIZE_REC), &v);
  if (rc == WK_OK)
    kread_q(kd(OFF_IMAGE_SIZE_REC) + 8, &next);
  a_image = rc == WK_OK && v == IMAGE_SIZE_REC && next == IMAGE_SIZE_1160;
  out("  image size   ktext+%#lx  %s  %#lx size %#lx (want %#lx %#lx)%s%s\n",
      OFF_IMAGE_SIZE_REC, mm(a_image), v, next, IMAGE_SIZE_REC,
      IMAGE_SIZE_1160, rc == WK_OK ? "" : " ", rc == WK_OK ? "" : wname[rc]);
}

static void more_anchors(uint64_t vmspace) {
  uint64_t v = 0, ptr = 0;
  char hex[65];
  int rc;

  rc = kread_q(kd(OFF_FACS), &v);
  a_facs = rc == WK_OK && (v >> 48) == 0xffffUL;
  out("  FACS ptr     ktext+%#lx  %s  %#lx", OFF_FACS, mm(a_facs), v);
  if (rc != WK_OK)
    out(" (%s)", wname[rc]);
  else if (v >= dmap && v - dmap < PA_LIMIT)
    out(" = dmap+%#lx", v - dmap);
  out("\n");

  rc = kdata_sha256(kd(OFF_IW620), IW620_LEN, hex);
  a_iw620 = rc == WK_OK && strcmp(hex, IW620_SHA256) == 0;
  out("  IW620 fw     ktext+%#lx  %s  len %#lx sha256 %s\n", OFF_IW620,
      mm(a_iw620), IW620_LEN, rc == WK_OK ? hex : wname[rc]);

  rc = kread_q(kd(OFF_EFI_ROOT_SLOT), &efi_slot);
  out("  EFI slot     ktext+%#lx  value %#lx, not followed",
      OFF_EFI_ROOT_SLOT, efi_slot);
  if (rc != WK_OK)
    out(" (%s)", wname[rc]);
  out("\n");

  if (kread_boot(vmspace + VMSPACE_VM_PMAP_1160, &ptr, 8) == 0)
    out("  off_1160 vm_map.pmap (vmspace+0x1d8) %s the SDK's embedded pmap\n",
        ptr == vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP ? "points at"
                                                       : "does NOT point at");
}

/* ---- pre-mutation readouts --------------------------------------------- */

static void idt_entry(int vec) {
  uint64_t g[2];
  int rc = kread_data(kd(OFF_IDT) + (uint64_t)vec * 16, g, sizeof(g));

  if (rc != WK_OK) {
    out("  IDT[%2d] %s\n", vec, wname[rc]);
    return;
  }
  uint64_t target = (g[0] & 0xffff) | ((g[0] >> 48) & 0xffff) << 16 |
                    (g[1] & 0xffffffffUL) << 32;
  out("  IDT[%2d] sel %#lx ist %lu type %#lx dpl %lu p %lu  ", vec,
      (g[0] >> 16) & 0xffff, (g[0] >> 32) & 7, (g[0] >> 40) & 0xf,
      (g[0] >> 45) & 3, (g[0] >> 47) & 1);
  if (target >= kd(0) && target < kd(KTEXT_LEN))
    out("target ktext+%#lx\n", target - kd(0));
  else
    out("target %#lx\n", target);
  rep("          raw %016lx %016lx\n", g[0], g[1]);
  if (vec == 1)
    out("          IDT[1] IST is %lu, loader needs 4: %s\n", (g[0] >> 32) & 7,
        ((g[0] >> 32) & 7) == 4 && ((g[0] >> 47) & 1) ? "ok" : "NO");
}

static void tss_table(void) {
  uint64_t rsp0[NCPU] = {0}, ist[NCPU][8];
  int ok_rsp0 = 1, ok_ist4 = 1, ist6_zero = 0, ist7_set = 0, read_ok = 1;

  memset(ist, 0, sizeof(ist));
  for (int cpu = 0; cpu < NCPU; cpu++) {
    uint8_t t[TSS_STRIDE];
    int rc =
        kread_data(kd(OFF_COMMON_TSS) + (uint64_t)cpu * TSS_STRIDE, t, sizeof(t));
    if (rc != WK_OK) {
      out("  TSS[%2d] %s\n", cpu, wname[rc]);
      read_ok = 0;
      continue;
    }
    memcpy(&rsp0[cpu], t + 4, 8);
    for (int i = 1; i <= 7; i++)
      memcpy(&ist[cpu][i], t + 0x24 + (i - 1) * 8, 8);
    rep("  TSS[%2d] rsp0 %016lx ist %016lx %016lx %016lx %016lx %016lx %016lx "
        "%016lx\n",
        cpu, rsp0[cpu], ist[cpu][1], ist[cpu][2], ist[cpu][3], ist[cpu][4],
        ist[cpu][5], ist[cpu][6], ist[cpu][7]);
    if ((rsp0[cpu] >> 47) != 0x1ffffUL)
      ok_rsp0 = 0;
    if (!ist[cpu][4])
      ok_ist4 = 0;
    for (int prior = 0; prior < cpu; prior++) {
      if (rsp0[cpu] == rsp0[prior])
        ok_rsp0 = 0;
      if (ist[cpu][4] == ist[prior][4])
        ok_ist4 = 0;
    }
    ist6_zero += ist[cpu][6] == 0;
    ist7_set += ist[cpu][7] != 0;
  }
  if (!read_ok)
    return;
  out("  TSS: 16 rows in the report\n");
  out("  rsp0 kernel and unique on 16/16: %s\n", ok_rsp0 ? "yes" : "NO");
  out("  IST4 set and unique on 16/16:    %s\n", ok_ist4 ? "yes" : "NO");
  out("  IST6 zero on %d/16%s\n", ist6_zero,
      ist6_zero == NCPU ? ""
                        : "  (something hooked is loaded, e.g. kstuff or "
                          "etaHEN; a clean boot is preferred)");
  out("  IST7 set on %d/16\n", ist7_set);
}

static void readouts(void) {
  static uint8_t buf[VBIOS_LEN];
  uint64_t facs = 0;
  char hex[65];
  int rc;

  section("Pre-mutation readouts (regular 11.60 offsets, reads only)");
  rc = kread_q(kd(OFF_FACS), &facs);
  out("  AcpiGbl_FACS %#lx, high 16 bits %#lx: %s\n", facs, facs >> 48,
      rc == WK_OK && (facs >> 48) == 0xffff ? "ok" : "NO");
  for (int i = 0; i < 4; i++)
    idt_entry((int[]){1, 13, 14, 30}[i]);
  tss_table();

  rc = kread_data(kd(OFF_DATA_CAVE), buf, 0x4000);
  if (rc == WK_OK) {
    uint64_t state;
    unsigned nonzero = 0;
    uint8_t digest[32];
    sha256_ctx ctx;
    for (int i = 0; i < 0x4000; i++)
      nonzero += buf[i] != 0;
    memcpy(&state, buf + 0x3000, 8);
    sha256_init(&ctx);
    sha256_update(&ctx, buf, 0x4000);
    sha256_final(&ctx, digest);
    sha256_hex(digest, hex);
    out("  DATA_CAVE ktext+0x2d02000: %u nonzero bytes of 0x4000, carrier "
        "state %#lx (0 = never armed)\n",
        nonzero, state);
    rep("            sha256 %s\n", hex);
  } else {
    out("  DATA_CAVE ktext+0x2d02000: %s\n", wname[rc]);
  }

  rc = kdata_sha256(kd(OFF_G_VBIOS), VBIOS_LEN, hex);
  if (rc == WK_OK) {
    kread_data(kd(OFF_G_VBIOS), buf, 2);
    out("  G_VBIOS ktext+0x3db7a40: sig %02x%02x, %s the regular VBIOS\n",
        buf[0], buf[1],
        strcmp(hex, VBIOS_SHA256_REGULAR) == 0 ? "same as" : "differs from");
    rep("            sha256 %s\n", hex);
  } else {
    out("  G_VBIOS ktext+0x3db7a40: %s\n", wname[rc]);
  }
}

static void page_walks(int gate) {
  char label[40];

  section("Page walks (page-table entries only, targets are not read)");
  print_walk("kdata base", kdata);
  if (meta_va)
    print_walk("boot metadata", meta_va);
  if (gate) {
    if (is_kptr(efi_slot)) {
      struct walk a, b;
      print_walk("EFI slot target", efi_slot);
      if (meta_va && walk_va(efi_slot, &a) == WK_OK &&
          walk_va(meta_va, &b) == WK_OK)
        out("  EFI slot target and boot metadata share a physical page: %s\n",
            (a.pa & ~(FRAME - 1)) == (b.pa & ~(FRAME - 1)) ? "yes" : "no");
    }
    for (int i = 0; i < 5; i++) {
      snprintf(label, sizeof(label), "code cave +%#x", i * 0x1000);
      print_walk(label, kd(OFF_CODE_CAVE) + (uint64_t)i * FRAME);
    }
  }
  print_walk("AP page dmap+0x3ffff000", dmap + 0x3ffff000UL);
  for (int src = 0; src < 2; src++)
    for (int i = 0; i < ncands[src]; i++) {
      struct range r = cands[src][i];
      snprintf(label, sizeof(label), "HV R (%s)", src ? "sysctl" : "meta");
      print_walk(label, dmap + r.base);
      snprintf(label, sizeof(label), "HV R+S-0x1000 (%s)",
               src ? "sysctl" : "meta");
      print_walk(label, dmap + r.base + r.size - FRAME);
    }
}

/* ---- CPU pinning ------------------------------------------------------- */

static void cpu_pin(void) {
  uint64_t old[2] = {0, 0}, want[2] = {1UL << 15, 0}, restored[2] = {0, 0};
  int have_old;

  section("CPU pinning (this thread only)");
  have_old = cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                                sizeof(old), (cpuset_t *)old) == 0;
  out("  running on CPU %d, affinity %s%#lx\n", sceKernelGetCurrentCpu(),
      have_old ? "" : "unknown ", old[0]);
  if (!have_old) {
    out("  pin to CPU 15: skipped; original affinity could not be saved "
        "(errno %d)\n",
        errno);
    return;
  }
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(want),
                         (const cpuset_t *)want)) {
    out("  pin to CPU 15: failed (errno %d)\n", errno);
    return;
  }
  sched_yield();
  usleep(1000);
  out("  pin to CPU 15: ok, now on CPU %d\n", sceKernelGetCurrentCpu());
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(old),
                         (const cpuset_t *)old)) {
    out("  restore original affinity: FAILED (errno %d)\n", errno);
    return;
  }
  if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                         sizeof(restored), (cpuset_t *)restored) ||
      memcmp(old, restored, sizeof(old)))
    out("  restore original affinity: FAILED readback\n");
  else
    out("  restore original affinity: ok (%#lx)\n", restored[0]);
}

/* ---- devices ----------------------------------------------------------- */

static const char *const pnp_keys[] = {
    "vendor",   "device",      "subvendor", "subdevice", "class",
    "subclass", "product",     "devclass",  "devsubclass", "intclass",
    "intsubclass", "_HID",     NULL,
};
static const char *const loc_keys[] = {
    "slot", "function", "dbsf", "bus", "port", "devaddr", "handle", NULL,
};

/* Keep only key=value tokens with a listed key. Drops serial numbers. */
static void keep_keys(const char *in, const char *const *keys, char *dst,
                      size_t cap) {
  size_t used = 0;
  char tok[128], txt[128];

  dst[0] = 0;
  while (*in) {
    size_t n = strcspn(in, " ");
    if (n && n < sizeof(tok)) {
      memcpy(tok, in, n);
      tok[n] = 0;
      char *eq = strchr(tok, '=');
      if (eq) {
        *eq = 0;
        for (int i = 0; keys[i]; i++) {
          if (strcmp(tok, keys[i]))
            continue;
          *eq = '=';
          clean(txt, sizeof(txt), tok, n);
          int w = snprintf(dst + used, cap - used, "%s%s", used ? " " : "", txt);
          if (w > 0 && (size_t)w < cap - used)
            used += (size_t)w;
          break;
        }
      }
    }
    in += n;
    while (*in == ' ')
      in++;
  }
}

/* Serial- or MAC-like: 8+ hex digits once separators are dropped, or 10+
 * characters mixing letters with 4+ digits. */
static int serial_like(const char *t, size_t n) {
  size_t hex = 0, digits = 0, alpha = 0, other = 0;

  for (size_t i = 0; i < n; i++) {
    char c = t[i];
    if (c == ':' || c == '-' || c == '.' || c == '_')
      continue;
    if (c >= '0' && c <= '9')
      digits++, hex++;
    else if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
      hex++, alpha++;
    else if ((c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z'))
      alpha++;
    else
      other++;
  }
  size_t len = digits + alpha + other;
  return (!other && len == hex && hex >= 8) ||
         (!other && len >= 10 && alpha && digits >= 4);
}

static void filter_desc(const char *in, char *dst, size_t cap) {
  size_t used = 0;
  char txt[96];

  dst[0] = 0;
  while (*in) {
    size_t n = strcspn(in, " ");
    if (n && !serial_like(in, n)) {
      clean(txt, sizeof(txt), in, MIN(n, sizeof(txt) - 1));
      int w = snprintf(dst + used, cap - used, "%s%s", used ? " " : "", txt);
      if (w > 0 && (size_t)w < cap - used)
        used += (size_t)w;
    }
    in += n;
    while (*in == ' ')
      in++;
  }
}

static void pci_devices(void) {
  static struct pci_conf conf[64];
  struct pci_conf_io io;
  int total = 0;
  char name[24];

  int fd = open("/dev/pci", O_RDONLY);
  if (fd < 0) {
    out("  /dev/pci: cannot open (errno %d)\n", errno);
    return;
  }
  memset(&io, 0, sizeof(io));
  io.match_buf_len = sizeof(conf);
  io.matches = conf;
  for (int round = 0; round < 16; round++) {
    if (ioctl(fd, PCIOCGETCONF, &io) < 0) {
      out("  /dev/pci: PCIOCGETCONF failed (errno %d)\n", errno);
      break;
    }
    if (io.status == PCI_GETCONF_LIST_CHANGED ||
        io.status == PCI_GETCONF_ERROR) {
      out("  /dev/pci: list status %d\n", (int)io.status);
      break;
    }
    for (unsigned i = 0; i < io.num_matches && i < 64; i++) {
      struct pci_conf *p = &conf[i];
      clean(name, sizeof(name), p->pd_name, sizeof(p->pd_name));
      out("  pci%u:%u:%u:%u  %04x:%04x  sub %04x:%04x  class %02x%02x%02x "
          "rev %02x  %s%lu\n",
          p->pc_sel.pc_domain, p->pc_sel.pc_bus, p->pc_sel.pc_dev,
          p->pc_sel.pc_func, p->pc_vendor, p->pc_device, p->pc_subvendor,
          p->pc_subdevice, p->pc_class, p->pc_subclass, p->pc_progif,
          p->pc_revid, name[0] ? name : "none", (unsigned long)p->pd_unit);
      total++;
    }
    if (io.status != PCI_GETCONF_MORE_DEVS)
      break;
  }
  close(fd);
  out("  /dev/pci: %d function(s)\n", total);
}

/* Walk the dev.* sysctl tree for %pnpinfo, %location and %desc. */
static void dev_sysctls(void) {
  int root[CTL_MAXNAME], oid[CTL_MAXNAME], next[CTL_MAXNAME];
  int q[CTL_MAXNAME + 2];
  size_t rootlen = CTL_MAXNAME, oidlen;
  int shown = 0;

  if (sysctlnametomib("dev", root, &rootlen)) {
    out("  sysctl dev tree: unavailable (errno %d)\n", errno);
    return;
  }
  memcpy(oid, root, rootlen * sizeof(int));
  oidlen = rootlen;
  for (int iter = 0; iter < 20000 && shown < 400; iter++) {
    size_t nextsz = sizeof(next);
    q[0] = 0;
    q[1] = 2; /* next OID */
    memcpy(q + 2, oid, oidlen * sizeof(int));
    if (sysctl(q, (u_int)(oidlen + 2), next, &nextsz, NULL, 0))
      break;
    size_t nextlen = nextsz / sizeof(int);
    if (nextlen < rootlen || nextlen > CTL_MAXNAME ||
        memcmp(next, root, rootlen * sizeof(int)))
      break;
    memcpy(oid, next, nextlen * sizeof(int));
    oidlen = nextlen;

    char name[256], val[512], txt[512], label[128];
    size_t namesz = sizeof(name) - 1, valsz = sizeof(val) - 1;
    memset(name, 0, sizeof(name));
    q[1] = 1; /* OID to name */
    memcpy(q + 2, oid, oidlen * sizeof(int));
    if (sysctl(q, (u_int)(oidlen + 2), name, &namesz, NULL, 0))
      continue;
    const char *leaf = strrchr(name, '.');
    int kind = !leaf                          ? 0
               : !strcmp(leaf, ".%pnpinfo")   ? 1
               : !strcmp(leaf, ".%location")  ? 2
               : !strcmp(leaf, ".%desc")      ? 3
                                              : 0;
    if (!kind)
      continue;
    memset(val, 0, sizeof(val));
    if (sysctl(oid, (u_int)oidlen, val, &valsz, NULL, 0))
      continue;
    if (kind == 1)
      keep_keys(val, pnp_keys, txt, sizeof(txt));
    else if (kind == 2)
      keep_keys(val, loc_keys, txt, sizeof(txt));
    else
      filter_desc(val, txt, 81);
    if (!txt[0])
      continue;
    rep("  %-36s %s\n", clean(label, sizeof(label), name, strlen(name)), txt);
    shown++;
  }
  out("  sysctl dev tree: %d line(s) (in the report)\n", shown);
}

/* ---- kernel data dump --------------------------------------------------- */

struct hole {
  uint64_t off;
  uint64_t len;
  int why;
};
static struct hole holes[512];
static int nholes, hole_overflow;
static uint64_t hole_bytes, why_bytes[WK_COUNT];
static uint64_t windows[KDATA_LEN / WINDOW_LEN];

static void hole_add(uint64_t off, uint64_t len, int why) {
  struct hole *h = nholes ? &holes[nholes - 1] : NULL;

  hole_bytes += len;
  why_bytes[why] += len;
  if (h && h->why == why && h->off + h->len == off) {
    h->len += len;
    return;
  }
  if (nholes < (int)(sizeof(holes) / sizeof(holes[0])))
    holes[nholes++] = (struct hole){off, len, why};
  else
    hole_overflow++;
}

/* Build paths in the dump, e.g. "W:/Build/J03675007/...": a quick build ID
 * for a console whose anchors do not match. */
static uint64_t build_hits, build_first = UINT64_MAX;
static char build_job[24];
static int build_jobs_differ;

static void scan_build(const uint8_t *p, uint64_t off) {
  static const char pat[] = "W:/Build/J";
  const size_t plen = sizeof(pat) - 1;

  for (size_t i = 0; i + plen < FRAME; i++) {
    if (p[i] != 'W' || memcmp(p + i, pat, plen))
      continue;
    char job[sizeof(build_job)];
    size_t n = 0;
    while (n + 1 < sizeof(job) && i + 9 + n < FRAME) {
      char c = (char)p[i + 9 + n];
      if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') || c == '_'))
        break;
      job[n++] = c;
    }
    job[n] = 0;
    if (i + 9 + n >= FRAME || p[i + 9 + n] != '/')
      continue; /* cut off at the frame end */
    build_hits++;
    if (build_first == UINT64_MAX) {
      build_first = off + i;
      memcpy(build_job, job, n + 1);
    } else if (strcmp(job, build_job)) {
      build_jobs_differ = 1;
    }
  }
}

static int dump_kdata(int gate, char sha_hex[65], const char **why) {
  static uint8_t page[PAGE16K];
  char part[256], final[256];
  struct statfs sf;
  sha256_ctx sha;
  uint8_t digest[32];
  uint64_t win = FNV64_INIT, off;
  int failed = 0;

  section("Kernel data dump");
  if (!gate)
    out("  anchors MISMATCH: dumping anyway. The page walk uses only SDK "
        "values; every frame is walked first, linear and write-back only.\n");
  if (statfs(out_dir, &sf)) {
    out("  statfs %s failed (errno %d), dump skipped\n", out_dir, errno);
    *why = "cannot check free space";
    return -1;
  }
  uint64_t avail = (uint64_t)sf.f_bavail * (uint64_t)sf.f_bsize;
  out("  %s: %lu MiB free\n", out_dir, avail >> 20);
  if (avail < KDATA_LEN + (2UL << 20)) {
    out("  need %lu MiB, have %lu MiB: free space on the drive and run "
        "again\n",
        (KDATA_LEN >> 20) + 2, avail >> 20);
    *why = "not enough free space";
    return -1;
  }
  out_path(part, sizeof(part), DUMP_BASE, ".bin.part");
  out_path(final, sizeof(final), DUMP_BASE, ".bin");
  int fd = open(part, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    out("  cannot create %s (errno %d), dump skipped\n", part, errno);
    *why = "cannot create the file";
    return -1;
  }
  out("  kdata %#lx..%#lx (%#lx bytes); every 4-KiB frame walked first, "
      "linear and write-back only\n",
      kdata, kdata + KDATA_LEN, KDATA_LEN);

  sha256_init(&sha);
  for (off = 0; off < KDATA_LEN; off += PAGE16K) {
    for (uint64_t f = 0; f < PAGE16K; f += FRAME) {
      int rc = kread_data(kdata + off + f, page + f, FRAME);
      if (rc != WK_OK)
        hole_add(off + f, FRAME, rc);
      else
        scan_build(page + f, off + f);
    }
    sha256_update(&sha, page, PAGE16K);
    win = fnv64_masked(win, page, PAGE16K);
    if ((off + PAGE16K) % WINDOW_LEN == 0) {
      windows[off / WINDOW_LEN] = win;
      win = FNV64_INIT;
    }
    if (write_all(fd, page, PAGE16K)) {
      out("  write failed at kdata+%#lx (errno %d), dump stopped\n", off,
          errno);
      failed = 1;
      break;
    }
    if ((off + PAGE16K) % PROGRESS_STEP == 0) {
      fsync(fd);
      if (report_fd >= 0)
        fsync(report_fd);
      out("  %3lu / %lu MiB, %#lx hole bytes so far\n", (off + PAGE16K) >> 20,
          KDATA_LEN >> 20, hole_bytes);
    }
  }
  if (fsync(fd))
    failed = 1;
  close(fd);
  if (failed) {
    unlink(part);
    out("  partial file removed\n");
    *why = "write error";
    return -1;
  }

  sha256_final(&sha, digest);
  sha256_hex(digest, sha_hex);
  if (rename(part, final)) {
    out("  rename %s failed (errno %d); the data is in the .part file\n",
        part, errno);
    *why = "rename failed";
    return -1;
  }
  out("  done: %s, %lu bytes (%#lx), sha256 %s\n", final, KDATA_LEN, KDATA_LEN,
      sha_hex);
  out("  regular reference dump (taken with hooks loaded) is 5705d4e9...; a "
      "live dump is not expected to match byte for byte\n");
  out("  holes (zero-filled): %d range(s), %#lx bytes%s\n", nholes, hole_bytes,
      hole_overflow ? ", list truncated" : "");
  for (int w = 0; w < WK_COUNT; w++)
    if (why_bytes[w])
      out("    %-14s %#lx bytes\n", wname[w], why_bytes[w]);
  for (int i = 0; i < nholes; i++) {
    const char *fmt = "    kdata+%#09lx..%#09lx %#lx bytes: %s\n";
    if (i < 16)
      out(fmt, holes[i].off, holes[i].off + holes[i].len, holes[i].len,
          wname[holes[i].why]);
    else
      rep(fmt, holes[i].off, holes[i].off + holes[i].len, holes[i].len,
          wname[holes[i].why]);
  }
  if (nholes > 16)
    out("    (%d more in the report)\n", nholes - 16);
  if (build_hits)
    out("  build paths in the dump: %lu, first at kdata+%#lx, job %s%s\n",
        build_hits, build_first, build_job,
        build_jobs_differ ? " (other jobs too)" : " (all the same)");
  else
    out("  build paths in the dump: none found\n");

  rep("\n  64-KiB window hashes (fnv64, kernel pointers masked; "
      "kdata_windows.py computes the same from a dump):\n");
  for (uint64_t w = 0; w < KDATA_LEN / WINDOW_LEN; w++)
    rep("%s %07lx %016lx%s", w % 4 ? "" : "win", w * WINDOW_LEN, windows[w],
        w % 4 == 3 || w + 1 == KDATA_LEN / WINDOW_LEN ? "\n" : "");
  return 0;
}

/* Past the window: walk only, to show whether kernel data runs on. */
static uint64_t beyond_mapped;

static void walk_beyond(void) {
  uint64_t base = kdata + KDATA_LEN, first = 0, last = 0, run = 0, linear = 0;
  int counts[WK_COUNT] = {0}, in_run = 1;

  section("Past the window (page walks only, 16 MiB, nothing read)");
  for (uint64_t off = 0; off < BEYOND_LEN; off += FRAME) {
    struct walk w;
    int rc = walk_va(base + off, &w);
    counts[rc]++;
    if (w.leaf < 0) {
      in_run = 0;
      continue;
    }
    if (!beyond_mapped++)
      first = off;
    last = off;
    run += in_run;
    linear += w.pa == kdata_pa + KDATA_LEN + off;
  }
  out("  %lu of %lu frames mapped", beyond_mapped, BEYOND_LEN / FRAME);
  if (beyond_mapped)
    out(", first at window end+%#lx, last at +%#lx, %lu contiguous from the "
        "window end, %lu linear with kdata",
        first, last, run, linear);
  out("\n ");
  for (int i = 0; i < WK_COUNT; i++)
    if (counts[i])
      out(" %s %d;", wname[i], counts[i]);
  out("\n");
}

/* ---- main --------------------------------------------------------------- */

static void out_reasons_skipped(void) {
  out("\n  Anchors do not match the regular 11.60 build. Skipped, because they "
      "use regular-build offsets: FACS, IW620 hash, EFI slot, off_1160 pmap "
      "pointer, IDT, TSS, DATA_CAVE, G_VBIOS, code-cave walks. The boot "
      "metadata is still found by signature");
  if (PROBE_MAP_ONLY)
    out(". This targeted build never creates a kdata dump.\n");
  else
    out(", and the kdata window is still dumped.\n");
}

int main(void) {
  uint32_t raw_fw;
  char stamp[32] = "unknown", sha_hex[65] = "", msg[256], path[256];
  const char *why = "not attempted";
  int dumped = -1, gate = 0, paging = 0, layout = 0;

  signal(SIGPIPE, SIG_IGN);
  raw_fw = kernel_get_fw_version();

  /* Refuse before opening or creating any file. This keeps a wrong-firmware
   * run from touching either USB or internal storage. */
  if (raw_fw != FW_1160_RAW) {
    out("ps5-1160-probe refused: firmware is %#010x; retail 11.60 is "
        "%#010x. No files were created.\n",
        raw_fw, FW_1160_RAW);
    notify("ps5-1160-probe refused: not firmware 11.60");
    return 1;
  }

  /* USB-only and fail closed. Raw kernel data must never fall back to the
   * console's internal filesystem. */
  if (open_report()) {
    out("ps5-1160-probe refused: no writable mounted USB drive found at "
        "/mnt/usb0..7. No kernel data was collected.\n");
    notify("ps5-1160-probe refused: mount a writable USB drive");
    return 1;
  }

  time_t now = time(NULL);
  struct tm tm;
  if (gmtime_r(&now, &tm))
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
  out("ps5-1160-probe %s, %s\n", PROBE_VERSION, stamp);
  out("Bounded collection: output goes to USB; probe logic makes no loader, "
      "kernel-text or HV patches and reads no HV target data or MMIO. "
      "Standard SDK runtime/KEX initialization applies.\n");
  out_path(path, sizeof(path), REPORT_BASE, ".txt");
  out("Report: %s\n", path);
  if (PROBE_MAP_ONLY)
    rep("Keep this report private: it comes from your console's kernel "
        "memory. This targeted build does not create a raw memory dump.\n");
  else
    rep("Keep this report and the dump private: they come from your "
        "console's kernel memory.\n");
  notify("ps5-1160-probe running (USB collection only)");

  ktext = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  kdata = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  identity(raw_fw);

  if (!is_kptr(kdata) || (kdata & (FRAME - 1)) || setup_paging()) {
    out("  page tables not confirmed; no kernel data reads\n");
    why = "page tables not confirmed";
  } else {
    paging = 1;
    layout = kernel_layout() == 0;
    if (!layout)
      why = "kdata base not confirmed";
  }

  memory_sysctls();
  if (layout) {
    gate_anchors();
    gate = a_build && a_image;
    if (!gate)
      out_reasons_skipped();
    boot_metadata(gate);
    image_summary();
  }
  hv_candidates();
  if (paging)
    hv_mapping_coverage();
  if (gate) {
    section("Identity anchors, continued (regular 11.60 offsets)");
    more_anchors(own_vmspace);
    readouts();
  }
  if (paging)
    page_walks(gate);
  cpu_pin();
  if (!PROBE_MAP_ONLY) {
    section("Devices (/dev/pci and sysctl, filtered: no serials or addresses)");
    pci_devices();
    dev_sysctls();
    out("  kernel bus device list: not walked (struct device offsets are not "
        "verified for 11.60)\n");
  }

  if (layout && !PROBE_MAP_ONLY) {
    if (!out_dir[0])
      why = "no output directory";
    else if (deny_full)
      why = "PA deny list or EFI map overflow";
    else
      dumped = dump_kdata(gate, sha_hex, &why);
    walk_beyond();
  }

  section("Summary");
  out("  firmware %#010x  SoC %#x%s  model %s\n", raw_fw, soc_id,
      soc_id == PRO_SOC_ID ? " (Pro)" : "", model);
  out("  page tables %s, kdata base %s%s", paging ? "ok" : "NOT confirmed",
      layout ? "ok" : "NOT confirmed",
      layout && !edge_ok ? " (frame below it is not execute-only)" : "");
  if (layout)
    out(", execute-only text %#lx bytes below kdata", kdata - text_lo);
  out("\n");
  out("  anchors: build %s, image-size %s, FACS %s, IW620 %s -> %s\n",
      mm(layout ? a_build : -1), mm(layout ? a_image : -1), mm(a_facs),
      mm(a_iw620),
      gate     ? "regular 11.60 build"
      : layout ? "NOT the regular build"
               : "not checked");
  if (meta_va)
    out("  boot metadata at kdata+%#lx, MODINFO_ADDR %s SDK ktext\n",
        meta_va - kdata, mod_addr == ktext ? "==" : "!=");
  else
    out("  boot metadata: not found\n");
  for (int src = 0; src < 2; src++) {
    out("  HV candidates (%s): ", src_name[src]);
    if (!have_map[src])
      out("no map\n");
    else if (!ncands[src])
      out("none\n");
    else
      out("%d, first R %#lx S %#lx\n", ncands[src], cands[src][0].base,
          cands[src][0].size);
  }
  if (PROBE_MAP_ONLY) {
    out("  kdata dump: intentionally disabled in targeted map/TSS build\n");
  } else if (dumped == 0) {
    out_path(path, sizeof(path), DUMP_BASE, ".bin");
    out("  kdata dump: %s, %#lx bytes, sha256 %s, %d hole range(s), %#lx "
        "hole bytes\n",
        path, KDATA_LEN, sha_hex, nholes, hole_bytes);
  } else {
    out("  kdata dump: not written (%s)\n", why);
  }
  if (layout && !PROBE_MAP_ONLY)
    out("  past the window: %lu of %lu frames mapped\n", beyond_mapped,
        BEYOND_LEN / FRAME);
  if (out_dir[0]) {
    out_path(path, sizeof(path), REPORT_BASE, ".txt");
    out("  report: %s\n", path);
  }
  if (PROBE_MAP_ONLY)
    out("  Send the report privately to the person who gave you this probe. "
        "Do not post it publicly.\n");
  else
    out("  Send both files privately to the person who gave you this probe. "
        "Do not post either publicly.\n");

  close_report();
  snprintf(msg, sizeof(msg), "ps5-1160-probe done. Files in %s",
           out_dir[0] ? out_dir : "stdout only");
  notify(msg);
  return 0;
}
