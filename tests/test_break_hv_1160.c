#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Exercise the real freestanding AP implementation against a synthetic DMAP. */
#include "../shellcode_break_hv/break_hv.c"

#define TEST_REGION_SIZE 0x2000000ULL
#define TEST_NEEDLE_CR3 0x12345000ULL
#define TEST_NEEDLE_RIP 0xffff800000001234ULL

static uint64_t load64(uint8_t *image, uint64_t region, uint64_t pa,
                       uint64_t offset) {
  return *(uint64_t *)(image + (pa - region) + offset);
}

static void store64(uint8_t *image, uint64_t region, uint64_t pa,
                    uint64_t offset, uint64_t value) {
  *(uint64_t *)(image + (pa - region) + offset) = value;
}

static void store32(uint8_t *image, uint64_t region, uint64_t pa,
                    uint64_t offset, uint32_t value) {
  *(uint32_t *)(image + (pa - region) + offset) = value;
}

static void populate_target(uint8_t *image, uint64_t region, uint64_t pa,
                            uint64_t pointer_lo, int self) {
  store64(image, region, pa, VMCB_NESTED_CTRL, 9);
  store32(image, region, pa, VMCB_ASID, 1);
  store64(image, region, pa, VMCB_NESTED_CR3, pointer_lo + 0x7000);
  store64(image, region, pa, VMCB_IOPM_BASE_PA, pointer_lo + 0x9000);
  store64(image, region, pa, VMCB_MSRPM_BASE_PA, pointer_lo + 0xb000);
  store32(image, region, pa, VMCB_CLEAN, 0xffffffffU);
  if (self) {
    store64(image, region, pa, VMCB_GUEST_CR3, TEST_NEEDLE_CR3);
    store64(image, region, pa, VMCB_GUEST_RIP, TEST_NEEDLE_RIP);
  }
}

static void run_case(uint64_t region, uint64_t scan_lo, uint64_t scan_hi,
                     int target_count, int add_old_disabled,
                     int invalid_self_msrpm, uint64_t expected_error) {
  uint8_t *image = calloc(1, TEST_REGION_SIZE);
  assert(image != NULL);

  const uint64_t first = scan_lo + 0x1000;
  const uint64_t pointer_lo = scan_lo;
  for (int i = 0; i < target_count; i++)
    populate_target(image, region, first + (uint64_t)i * 0x2000,
                    pointer_lo, i == 0);

  if (invalid_self_msrpm)
    store64(image, region, first, VMCB_MSRPM_BASE_PA, 0);

  const uint64_t old_disabled_pa = first + 0x100000;
  if (add_old_disabled) {
    populate_target(image, region, old_disabled_pa, pointer_lo, 0);
    store64(image, region, old_disabled_pa, VMCB_NESTED_CTRL, 8);
    store32(image, region, old_disabled_pa, VMCB_CLEAN, 0);
  }

  uint64_t result[8] = {0};
  uint64_t ext[32] = {0};
  uint64_t param[9] = {0};
  param[1] = (uint64_t)(uintptr_t)image - region;
  param[2] = (uint64_t)(uintptr_t)result;
  param[3] = scan_lo;
  param[4] = (uint64_t)(uintptr_t)ext;
  param[5] = TEST_NEEDLE_RIP;
  param[6] = TEST_NEEDLE_CR3;
  param[7] = AP_MODE_1160;
  param[8] = scan_hi;

  vmcb_disable_np(param);
  assert(ext[0] == expected_error);

  if (expected_error == 0) {
    assert(ext[8] == 16 && ext[9] == 16);
    assert(ext[28] == ext[29]);
    for (int i = 0; i < 16; i++) {
      const uint64_t pa = first + (uint64_t)i * 0x2000;
      assert(ext[10 + i] == pa);
      assert(load64(image, region, pa, VMCB_NESTED_CTRL) == 8);
      assert(*(uint32_t *)(image + (pa - region) + VMCB_CLEAN) == 0);
    }
    if (add_old_disabled)
      assert(load64(image, region, old_disabled_pa, VMCB_NESTED_CTRL) == 8);
  } else {
    assert(ext[8] == 0 && ext[9] == 0);
    for (int i = 0; i < target_count; i++) {
      const uint64_t pa = first + (uint64_t)i * 0x2000;
      assert(load64(image, region, pa, VMCB_NESTED_CTRL) == 9);
    }
  }

  free(image);
}

int main(void) {
  /* The Pro path ignores unrelated already-disabled frames and pins its list. */
  run_case(PRO_REGION_LO, PRO_SCAN_LO, PRO_SCAN_HI, 16, 1, 0, 0);
  run_case(PRO_REGION_LO, PRO_SCAN_LO, PRO_SCAN_HI, 15, 0, 0, 4);
  run_case(PRO_REGION_LO, PRO_SCAN_LO, PRO_SCAN_HI, 17, 0, 0, 4);
  run_case(PRO_REGION_LO, PRO_SCAN_LO, PRO_SCAN_HI, 16, 0, 1, 3);

  /* Regular keeps the original predicate, including no MSRPM self gate. */
  run_case(REGULAR_SCAN_LO, REGULAR_SCAN_LO, REGULAR_SCAN_HI,
           16, 0, 1, 0);

  uint64_t result[8] = {0};
  uint64_t ext[32] = {0};
  uint64_t param[9] = {0};
  param[2] = (uint64_t)(uintptr_t)result;
  param[3] = 0xdead0000ULL;
  param[4] = (uint64_t)(uintptr_t)ext;
  param[7] = AP_MODE_1160;
  param[8] = 0xdeae0000ULL;
  vmcb_disable_np(param);
  assert(ext[0] == 1);
  assert(ext[8] == 0 && ext[9] == 0);

  /* A partially committed list restores nctl=9 even if CLEAN was nonzero. */
  uint8_t *image = calloc(1, TEST_REGION_SIZE);
  assert(image != NULL);
  const uint64_t dmap = (uint64_t)(uintptr_t)image - PRO_REGION_LO;
  const uint64_t first = PRO_SCAN_LO + 0x1000;
  uint64_t candidates[TARGET_COUNT] = {first, first + 0x2000};
  populate_target(image, PRO_REGION_LO, candidates[0], PRO_SCAN_LO, 0);
  populate_target(image, PRO_REGION_LO, candidates[1], PRO_SCAN_LO, 0);
  store64(image, PRO_REGION_LO, candidates[0], VMCB_NESTED_CTRL, 8);
  store64(image, PRO_REGION_LO, candidates[1], VMCB_NESTED_CTRL, 8);
  store32(image, PRO_REGION_LO, candidates[0], VMCB_CLEAN, 1);
  store32(image, PRO_REGION_LO, candidates[1], VMCB_CLEAN, 1);
  memset(ext, 0, sizeof(ext));
  rollback_candidates(dmap, 1, PRO_SCAN_LO, PRO_SCAN_HI,
                      PRO_REGION_LO, PRO_REGION_HI, candidates, ext, 2);
  assert(ext[EXT_ROLLBACK_WRITTEN] == 2);
  assert(ext[EXT_ROLLBACK_VERIFIED] == 2);
  assert(load64(image, PRO_REGION_LO, candidates[0], VMCB_NESTED_CTRL) == 9);
  assert(load64(image, PRO_REGION_LO, candidates[1], VMCB_NESTED_CTRL) == 9);
  free(image);

  return 0;
}
