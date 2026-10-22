#ifndef PS5_1160_CENSUS_PARAMS_H
#define PS5_1160_CENSUS_PARAMS_H

#include <stdint.h>

#define CENSUS_REPORT_MAGIC 0x53554E4543353150ULL /* "P15CENUS" */
#define CENSUS_REPORT_VERSION 3ULL
#define CENSUS_STATE_ENTERED 0x455245544E452D31ULL /* "1-ENTERE" */
#define CENSUS_STATE_DONE 0x454E4F442D315043ULL    /* "CP1-DONE" */
#define CENSUS_CANDIDATE_MAX 32

/* Relocation-safe FNV-1a reference windows verified against the authenticated
 * regular 11.60 HV reference.  Its SHA-256 is documented in the census
 * README.  Only these hashes, never HV bytes, are compiled into the payload. */
#define CENSUS_BOUNDARY_OFFSET 0x67d9ULL
#define CENSUS_BOUNDARY_LENGTH 0x140ULL
#define CENSUS_BOUNDARY_FNV 0x18f1b0469f16d1abULL
#define CENSUS_CAVE_OFFSET 0x6ec0ULL
#define CENSUS_CAVE_LENGTH 0x80ULL
#define CENSUS_CAVE_FNV 0x1111e7a924292b25ULL
#define CENSUS_VMEXIT_OFFSET 0x47540ULL
#define CENSUS_VMEXIT_LENGTH 0x40ULL
#define CENSUS_VMEXIT_FNV 0xfb06e5672b906885ULL

enum census_param_index {
  CENSUS_P_INIT_CB,
  CENSUS_P_DMAP,
  CENSUS_P_REPORT,
  CENSUS_P_HV_BASE,
  CENSUS_P_HV_SIZE,
  CENSUS_P_NEEDLE_RIP,
  CENSUS_P_NEEDLE_CR3,
  CENSUS_P_BITMAP,
  CENSUS_P_BITMAP_BYTES,
  CENSUS_P_TSS_BASE,
  CENSUS_P_SAVED_ISTS,
  CENSUS_P_CARRIER_STATE,
  CENSUS_P_SCAN_LO,
  CENSUS_P_SCAN_HI,
  CENSUS_P_CODE_BASE,
  CENSUS_P_COUNT,
};

struct census_report {
  uint64_t magic;
  uint64_t version;
  uint64_t size;
  uint64_t state;
  uint64_t error;
  uint64_t hv_base;
  uint64_t hv_size;
  uint64_t scan_lo;
  uint64_t scan_hi;
  uint64_t mapped_pages;
  uint64_t scanned_pages;
  uint64_t self_pa;
  uint64_t self_count;
  uint64_t self_nctl;
  uint64_t self_ncr3;
  uint64_t self_asid;
  uint64_t self_iopm;
  uint64_t self_msrpm;
  uint64_t target_count;
  uint64_t candidate_recorded;
  uint64_t fields_hash_before;
  uint64_t fields_hash_after;
  uint64_t restore_count;
  uint64_t restore_readback_count;
  uint64_t carrier_cleared;
  uint64_t code_base;
  uint64_t boundary_hash;
  uint64_t cave_hash;
  uint64_t vmexit_hash;
  uint64_t anchor_valid_mask;
  uint64_t anchor_match_mask;
  uint64_t candidate_pa[CENSUS_CANDIDATE_MAX];
};

_Static_assert(sizeof(struct census_report) <= 0x400,
               "census report exceeds its data-cave slot");

#endif
