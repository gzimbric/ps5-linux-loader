#include "boot_linux.h"
#include "../include/config.h"
#include "../include/linux.h"
#if SHELLCODE_1160_ONLY
#include "../shellcode_hv_port_1160/shellcode_hv_port_1160.h"
#define shellcode_hv_bin shellcode_hv_port_1160_bin
#define shellcode_hv_bin_len shellcode_hv_port_1160_bin_len
#else
#include "../shellcode_hv/shellcode_hv.h"
#endif
#include "shellcode_kernel_args_validate.h"
#include "utils.h"

#define DIG1TRANSMITTERCONTROL 0x4c

#define TRANSMITTER_CONTROL_ENABLE 1
#define TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS 11

int (*transmitter_control)(int cmd, void *control) = NULL;
int (*mp3_initialize)(int vmid) = NULL;
int (*mp3_invoke)(int cmd_id, void *req, void *rsp) = NULL;

uint64_t g_vbios;

typedef struct {
  uint64_t flags;
  uint64_t addr;
  uint64_t size;
} __attribute__((packed)) SceSblHvShmTmrPtState;

typedef uint64_t SceSblHvShmTmrIdBmp;
typedef uint16_t SceSblHvShmTmrPtIdBmp;

typedef struct {
  uint32_t sig;
  uint32_t ver;
  SceSblHvShmTmrPtIdBmp tmrMapPts[64];
  SceSblHvShmTmrIdBmp tmrOvlpIds[64];
  SceSblHvShmTmrPtState tmrPtStates[64];
  uint32_t nmiCounts[16];
  uint8_t reserved[64];
} __attribute__((packed)) SceSblHvShm;

typedef struct {
  uint8_t lanenum;
  uint32_t rate;
  uint32_t pad;
  uint32_t lane_setting_1;
  uint32_t lane_setting_2;
} transmitter_args;

#if !SHELLCODE_1160_HEADLESS
struct dig_transmitter_control_parameters_v1_6 {
  uint8_t phyid;
  uint8_t action;
  union {
    uint8_t digmode;
    uint8_t dplaneset;
  } mode_laneset;
  uint8_t lanenum;
  uint32_t symclk_10khz;
  uint8_t hpdsel;
  uint8_t digfe_sel;
  uint8_t connobj_id;
  uint8_t reserved;
  uint32_t reserved1;
};
#endif

static struct linux_info info;

#if !SHELLCODE_1160_HEADLESS
#if SHELLCODE_1160_DIAGNOSTIC
#ifndef PS5_1160_DIAG_PRE_STAGE
#define PS5_1160_DIAG_PRE_STAGE 5
#endif
#ifndef PS5_1160_DIAG_CLEAR_MP3_BUFFERS
#define PS5_1160_DIAG_CLEAR_MP3_BUFFERS 0
#endif
_Static_assert(PS5_1160_DIAG_PRE_STAGE >= 0 &&
                   PS5_1160_DIAG_PRE_STAGE <= 5,
               "11.60 diagnostic pre-display stage is out of range");
_Static_assert(PS5_1160_DIAG_CLEAR_MP3_BUFFERS == 0 ||
                   PS5_1160_DIAG_CLEAR_MP3_BUFFERS == 1,
               "11.60 diagnostic MP3 clear gate must be 0 or 1");
volatile const uint32_t ps5_diag_pre_stage_1160 =
    PS5_1160_DIAG_PRE_STAGE;
volatile const uint32_t ps5_diag_clear_mp3_buffers_1160 =
    PS5_1160_DIAG_CLEAR_MP3_BUFFERS;
#endif

#define MP3_REQ_WORDS 1281ULL
#define MP3_RSP_WORDS 1282ULL
#if SHELLCODE_1160_ONLY
#define MP3_RSP_OFFSET 0x1000ULL
#define MP3_REQ_OFFSET 0x2420ULL

/*
 * Sonic keeps these two MP3 IPC buffers in the wake blob's zero-filled data.
 * The authenticated 11.60 executable cave is 0x5000 bytes, and embedding the
 * same 0x280c bytes would make the otherwise identical display-enabled blob
 * 792 bytes too large.  The checked linux_info alias owns one complete 0x4000
 * page; linux_info occupies 0xc38 bytes, leaving a disjoint, retained tail for
 * the exact same buffers without moving the proven cave.  Preserve Sonic's
 * observed layout: the 0x1408-byte response buffer first, an 0x18-byte gap,
 * then the 0x1404-byte request buffer.
 */
_Static_assert(sizeof(struct linux_info) <= MP3_RSP_OFFSET,
               "linux_info overlaps MP3 response buffer");
_Static_assert((MP3_REQ_OFFSET & 31) == 0 && (MP3_RSP_OFFSET & 31) == 0,
               "Sonic MP3 buffers must remain 32-byte aligned");
_Static_assert(MP3_RSP_OFFSET + MP3_RSP_WORDS * sizeof(int) + 0x18ULL ==
                   MP3_REQ_OFFSET,
               "Sonic MP3 response/request gap changed");
_Static_assert(MP3_REQ_OFFSET + MP3_REQ_WORDS * sizeof(int) <= PAGE_SIZE,
               "MP3 buffers exceed the retained linux_info page");

static int *mp3_req_buffer(void) {
  return (int *)(args.linux_info_va + MP3_REQ_OFFSET);
}

static int *mp3_rsp_buffer(void) {
  return (int *)(args.linux_info_va + MP3_RSP_OFFSET);
}
#else
static int mp3_req[MP3_REQ_WORDS], mp3_rsp[MP3_RSP_WORDS];

static int *mp3_req_buffer(void) { return mp3_req; }

static int *mp3_rsp_buffer(void) { return mp3_rsp; }
#endif

static void clear_mp3_buffers(void) {
  int *req = mp3_req_buffer();
  int *rsp = mp3_rsp_buffer();

  for (uint64_t i = 0; i < MP3_REQ_WORDS; i++)
    req[i] = 0;
  for (uint64_t i = 0; i < MP3_RSP_WORDS; i++)
    rsp[i] = 0;
}
#endif

static inline void stac(void) { __asm__ volatile("stac" : : : "cc"); }

static inline void clac(void) { __asm__ volatile("clac" : : : "cc"); }

static inline uint64_t vmmcall(uint64_t nr, uint64_t a0, uint64_t a1,
                               uint64_t a2) {
  uint64_t ret;
  __asm__ volatile("vmmcall"
                   : "=a"(ret)
                   : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
                   : "memory");
  return ret;
}

#if !SHELLCODE_1160_HEADLESS
static uint64_t get_hv_shm(void) {
  if (args.fw_version >= 0x0500 && args.fw_version < 0x0600) {
    return 0x62a01000;
  } else if (args.fw_version >= 0x0600 && args.fw_version < 0x0800) {
    return 0x62a22000;
  }
  return -1;
}

static int dp_enable_link_phy(int lanenum, int linkrate) {
  struct dig_transmitter_control_parameters_v1_6 params = {};
  params.phyid = 0;
  params.action = TRANSMITTER_CONTROL_ENABLE;
  params.mode_laneset.digmode = 0;
  params.lanenum = lanenum;
  params.symclk_10khz = 27000 * linkrate / 10;
  params.hpdsel = 0;
  params.digfe_sel = 0;
  params.connobj_id = 0;

  return transmitter_control(DIG1TRANSMITTERCONTROL, &params);
}

static uint64_t read_tsc(void) {
  uint32_t lo;
  uint32_t hi;
  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

static void wait_for_transmitter(void) {
  const uint64_t start = read_tsc();

  /* Sonic's 13.60 wake blob waits through TSC delta 349,999,999. */
  while (read_tsc() - start <= 349999999ULL)
    __asm__ volatile("pause");
}

static int mp3_set_hdcp_packet(int be, int mode) {
  int *req = mp3_req_buffer();
  req[0] = be;
  req[1] = mode;
  return mp3_invoke(21, req, mp3_rsp_buffer());
}

static int mp3_enable_output(int be, int mode) {
  int *req = mp3_req_buffer();
  req[0] = be;
  req[1] = mode;
  return mp3_invoke(22, req, mp3_rsp_buffer());
}
#endif

static void install_hv_code(void) {
  // Install identity map for HV
  uint64_t identity_cr3 = cave_hv_paging;
  uint64_t identity_pml4_0 = identity_cr3 + 0x1003ULL;
  uint64_t l40_l3_addr = PAGE_PA(identity_pml4_0); // addr PML4[0]
  uint64_t identity_pml40_l3[] = {
      0x0000000000000083, // P, RW, US=0 - 0 GB to 1 GB
      0x0000000040000083, // P, RW, US=0 - 1 GB to 2 GB
      0x0000000080000083, // P, RW, US=0 - 3 GB to 3 GB
      0x00000000C0000083, // P, RW, US=0 - 4 GB to 4 GB
      0x0000000100000083  // P, RW, US=0 - 5 GB to 6 GB --> Our paging structure
  };
  uint64_t l3_size = sizeof(identity_pml40_l3) / sizeof(identity_pml40_l3[0]);

  // Create the map in memory
  *(uint64_t *)PHYS_TO_DMAP(identity_cr3) = identity_pml4_0;
  for (uint64_t i = 0; i < l3_size; i++) {
    *(uint64_t *)PHYS_TO_DMAP(l40_l3_addr + i * 8) = identity_pml40_l3[i];
  }

  /* The Pro trampoline lives above the five low 1-GiB identity leaves. */
  const uint64_t cave_index = args.hv_code_cave_pa >> 30;
  _Static_assert((HV_CAVE_PRO_1160 >> 30) == 0x23,
                 "11.60 Pro cave identity index changed");
  if (cave_index >= l3_size && cave_index < 512) {
    *(uint64_t *)PHYS_TO_DMAP(l40_l3_addr + cave_index * 8) =
        (cave_index << 30) | 0x83;
  }

  // Install shellcode_hv
  memcpy((void *)PHYS_TO_DMAP(cave_hv_code), shellcode_hv_bin,
         shellcode_hv_bin_len);
}

void patch_hv(void) {
  if (args.hv_code_cave_pa > 0x7fffffffULL) {
    uint8_t shellcode_jmp[] = {
        0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, // movabs rax, 0xAAAAAAAAAAAAAAAA
        0xFF, 0xE0              // jmp rax
    };
    _Static_assert(sizeof(shellcode_jmp) == 12,
                   "Pro VMEXIT absolute-jump patch size changed");
    _Static_assert(HV_VMEXIT_PRO_1160 >=
                           HV_CODE_BASE_PRO_1160 + UINT64_C(0x47540) &&
                       HV_VMEXIT_PRO_1160 + sizeof(shellcode_jmp) <=
                           HV_CODE_BASE_PRO_1160 + UINT64_C(0x47580),
                   "Pro VMEXIT patch left its authenticated window");
    *(uint64_t *)(&shellcode_jmp[2]) = args.hv_code_cave_pa;
    memcpy((void *)PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
           sizeof(shellcode_jmp));
  } else {
    uint8_t shellcode_jmp[] = {
        0x48, 0xC7, 0xC0, 0xAA, 0xAA, 0xAA,
        0xAA,      // mov rax, 0xAAAAAAAA
        0xFF, 0xE0 // jmp rax
    };
    _Static_assert(sizeof(shellcode_jmp) == 9,
                   "regular VMEXIT absolute-jump patch size changed");
    *(uint32_t *)(&shellcode_jmp[3]) = (uint32_t)args.hv_code_cave_pa;
    memcpy((void *)PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
           sizeof(shellcode_jmp));
  }

  uint8_t shellcode_identity_and_jmp[] = {
      0x48, 0xB8, 0xAA, 0xAA, 0xAA,
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // movabs rax, 0xAAAAAAAAAAAAAAAA
      0x0F, 0x22, 0xD8,             // mov    cr3, rax
      0x48, 0xB8, 0xAA, 0xAA, 0xAA,
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // movabs rax, 0xAAAAAAAAAAAAAAAA
      0xFF, 0xE0                    // jmp    rax
  };
  _Static_assert(sizeof(shellcode_identity_and_jmp) == 25,
                 "HV identity transition stub size changed");
  _Static_assert(HV_CAVE_PRO_1160 >=
                         HV_CODE_BASE_PRO_1160 + UINT64_C(0x6ec0) &&
                     HV_CAVE_PRO_1160 + sizeof(shellcode_identity_and_jmp) <=
                         HV_CODE_BASE_PRO_1160 + UINT64_C(0x6f40),
                 "Pro cave patch left its authenticated window");

  // Update CR3 PA (from config)
  *(uint64_t *)(&shellcode_identity_and_jmp[2]) = cave_hv_paging;
  // Update HV shellcode cave
  *(uint64_t *)(&shellcode_identity_and_jmp[15]) = cave_hv_code;

  // Install shellcode to update CR3 and jump to main HV shellcode
  memcpy((void *)PHYS_TO_DMAP(args.hv_code_cave_pa), shellcode_identity_and_jmp,
         sizeof(shellcode_identity_and_jmp));
}

void boot_linux(void) {
  patch_hv();

  // Common bootloader code
  install_hv_code();

  /* The same ELF serves regular and Pro consoles, and both get the same
   * VBIOS/DP/MP3 display handoff.  Without it the Pro's HDMI bridge never
   * turns its output on: Linux trains DP-1 but the TV shows no signal. */
  memcpy(&info, (void *)args.linux_info_va, sizeof(struct linux_info));

#if !SHELLCODE_1160_HEADLESS
#if SHELLCODE_1160_DIAGNOSTIC
  const uint32_t diag_pre_stage = ps5_diag_pre_stage_1160;

  if (diag_pre_stage >= 1 && g_vbios != 0)
    memcpy((void *)PHYS_TO_DMAP(0xC0000), (void *)g_vbios, 0x10000);

  if (diag_pre_stage >= 2 && transmitter_control != NULL) {
    dp_enable_link_phy(4, 30);
    wait_for_transmitter();
  }

  if (diag_pre_stage >= 3 && mp3_initialize != NULL && mp3_invoke != NULL) {
    if (ps5_diag_clear_mp3_buffers_1160 != 0)
      clear_mp3_buffers();
    mp3_initialize(0);
    if (diag_pre_stage >= 4)
      mp3_set_hdcp_packet(0, 1);
    if (diag_pre_stage >= 5)
      mp3_enable_output(0, 1);
  }
#else
  if (g_vbios != 0)
    memcpy((void *)PHYS_TO_DMAP(0xC0000), (void *)g_vbios, 0x10000);

  // Enable DP phys link.
  if (transmitter_control != NULL) {
    dp_enable_link_phy(4, 30);
    wait_for_transmitter();
  }

  // Initialize hdcp in mp3.
  if (mp3_initialize != NULL && mp3_invoke != NULL) {
#if !SHELLCODE_1160_ONLY
    clear_mp3_buffers();
#endif
    mp3_initialize(0);
    mp3_set_hdcp_packet(0, 1);
    mp3_enable_output(0, 1);
  }
#endif
#endif

  // Copy bzImage and initrd into contiguous memory.
  info.n_tmrs = 0;
#if !SHELLCODE_1160_HEADLESS
  if (args.fw_version >= 0x0500 && args.fw_version < 0x0800) {
    SceSblHvShm *shm = (SceSblHvShm *)PHYS_TO_DMAP(get_hv_shm());

    for (int i = 0; i < 64; i++) {
      if (shm->tmrPtStates[i].flags & 1) {
        info.tmrs[info.n_tmrs].start = shm->tmrPtStates[i].addr;
        info.tmrs[info.n_tmrs].end = shm->tmrPtStates[i].addr + shm->tmrPtStates[i].size;
        printf("tmr: %lx-%lx\n", info.tmrs[info.n_tmrs].start, info.tmrs[info.n_tmrs].end);
        info.n_tmrs++;
      }
    }
  }
#endif

  uintptr_t bzimage = info.bzimage;
  uintptr_t initrd = info.initrd;

  info.bzimage = cave_bzImage;
  info.initrd = cave_bzImage + ALIGN_UP(info.bzimage_size, PAGE_SIZE);

  memcpy((void *)PHYS_TO_DMAP(cave_linux_info), &info,
         sizeof(struct linux_info));
  memcpy((void *)PHYS_TO_DMAP(info.bzimage), (void *)bzimage,
         info.bzimage_size);
  memcpy((void *)PHYS_TO_DMAP(info.initrd), (void *)initrd, info.initrd_size);
}
