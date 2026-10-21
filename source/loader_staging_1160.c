#include "loader_staging_1160.h"

#if FW_1160_PORT

#include "config.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define X86_PAGE_SIZE 0x1000ULL
#define TABLE_FLAGS (PG_B_P | PG_B_RW)
#define MAX_COMBINED_MAPPING (160ULL * 1024ULL * 1024ULL)

static_assert(PAGE_SIZE == X86_PAGE_SIZE * 4,
              "11.60 staging requires four 4-KiB frames per logical page");

struct alias_page_1160 {
  uint64_t target_va;
  const uint8_t *source;
  uint64_t source_pa;
};

struct journal_entry_1160 {
  uint64_t entry_va;
  uint64_t old_value;
};

struct owned_table_1160 {
  void *mapping;
  uint64_t pa;
};

struct alias_tx_1160 {
  uint64_t syscore_pml4;
  uint64_t source_pml4;
  struct journal_entry_1160 *journal;
  size_t journal_count;
  size_t journal_capacity;
  struct owned_table_1160 *tables;
  size_t table_count;
  size_t table_capacity;
};

struct retained_staging_1160 {
  void *bzimage;
  size_t bzimage_mapping_size;
  void *initrd;
  size_t initrd_mapping_size;
  void *info_page;
  struct alias_tx_1160 tx;
  int active;
};

/* One successful loader invocation owns these mappings until rest/wake. */
static struct retained_staging_1160 retained_staging;

static void checkpoint(const char *text) {
  printf("11.60 alias staging: %s\n", text);
  fflush(stdout);
}

static int add_size(size_t a, size_t b, size_t *out) {
  if (a > SIZE_MAX - b)
    return -1;
  *out = a + b;
  return 0;
}

static int read_kernel(uint64_t address, void *value, size_t size) {
  memset(value, 0, size);
  return kernel_copyout(address, value, size) == 0 ? 0 : -1;
}

static int write_kernel(uint64_t address, const void *value, size_t size) {
  return kernel_copyin(value, address, size) == 0 ? 0 : -1;
}

static int read_entry(uint64_t entry_va, uint64_t *value) {
  return read_kernel(entry_va, value, sizeof(*value));
}

static int is_kernel_pointer(uint64_t value) {
  return value >= 0xFFFF800000000000ULL;
}

static int get_proc_pmap_checked(pid_t pid, flat_pmap *flat_out) {
  uint64_t proc = kernel_get_proc(pid);
  uint64_t vmspace = 0;
  uint64_t pmap = 0;
  flat_pmap flat;

  memset(&flat, 0, sizeof(flat));
  if (!is_kernel_pointer(proc) ||
      read_entry(proc + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace) ||
      !is_kernel_pointer(vmspace) ||
      read_entry(vmspace + env_offset.VMSPACE_VM_PMAP, &pmap) ||
      !is_kernel_pointer(pmap) || (pmap & 7) != 0 ||
      read_kernel(pmap, &flat, sizeof(flat)) ||
      !is_kernel_pointer(flat.pm_pml4) ||
      (flat.pm_pml4 & (X86_PAGE_SIZE - 1)) != 0 || !flat.pm_cr3 ||
      (flat.pm_cr3 & (X86_PAGE_SIZE - 1)) != 0 ||
      PAGE_PA(flat.pm_cr3) != flat.pm_cr3 || flat.pm_pml4 <= flat.pm_cr3 ||
      flat.pm_pml4 - flat.pm_cr3 != dmap)
    return -1;

  *flat_out = flat;
  return 0;
}

static int translate_user_checked(uint64_t pml4, uint64_t va,
                                  uint64_t *pa_out) {
  uint64_t table_va = pml4;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t entry = 0;
    uint64_t entry_va = table_va + ((va >> shift) & 0x1FF) * 8;

    if (read_entry(entry_va, &entry) || !PAGE_P(entry))
      return -1;
    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      uint64_t page_size = P_SIZE(level);
      *pa_out = PAGE_PA(entry) | (va & (page_size - 1));
      return 0;
    }
    if (level == 3) {
      *pa_out = PAGE_PA(entry) | (va & (X86_PAGE_SIZE - 1));
      return 0;
    }
    table_va = pa_to_dmap(PAGE_PA(entry));
  }
  return -1;
}

/* Validate all four hardware frames, including their bytes through DMAP. */
static int source_page_pa(uint64_t source_pml4, const uint8_t *source,
                          uint64_t *base_pa) {
  uint8_t physical[X86_PAGE_SIZE];
  uint64_t first = 0;

  if (((uintptr_t)source & (PAGE_SIZE - 1)) != 0)
    return -1;
  for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
    uint64_t pa = 0;
    if (translate_user_checked(source_pml4,
                               (uint64_t)(uintptr_t)source + sub, &pa) ||
        !pa || (pa & (X86_PAGE_SIZE - 1)))
      return -1;
    if (sub == 0)
      first = pa;
    else if (pa != first + sub)
      return -1;
    if (read_kernel(pa_to_dmap(pa), physical, sizeof(physical)) ||
        memcmp(physical, source + sub, sizeof(physical)) != 0)
      return -1;
  }
  *base_pa = first;
  return 0;
}

/* A missing parent means every descendant is absent; large parents refuse. */
static int lookup_pte(uint64_t pml4, uint64_t va, uint64_t *pte_va,
                      int *absent) {
  uint64_t entry = 0;
  uint64_t entry_va;

  *absent = 0;
  entry_va = pml4 + pmap_pml4e_index(va) * 8;
  if (read_entry(entry_va, &entry))
    return -1;
  if (!PAGE_P(entry)) {
    *absent = 1;
    return 0;
  }

  entry_va = pa_to_dmap(PAGE_PA(entry)) + pmap_pdpe_index(va) * 8;
  if (read_entry(entry_va, &entry))
    return -1;
  if (!PAGE_P(entry)) {
    *absent = 1;
    return 0;
  }
  if (PAGE_PS(entry))
    return -1;

  entry_va = pa_to_dmap(PAGE_PA(entry)) + pmap_pde_index(va) * 8;
  if (read_entry(entry_va, &entry))
    return -1;
  if (!PAGE_P(entry)) {
    *absent = 1;
    return 0;
  }
  if (PAGE_PS(entry))
    return -1;

  *pte_va = pa_to_dmap(PAGE_PA(entry)) + pmap_pte_index(va) * 8;
  return 0;
}

static int preflight_target_page(uint64_t pml4, uint64_t va) {
  for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
    uint64_t pte_va = 0;
    uint64_t pte = 0;
    int absent = 0;

    if (lookup_pte(pml4, va + sub, &pte_va, &absent))
      return -1;
    if (!absent && (read_entry(pte_va, &pte) || PAGE_P(pte)))
      return -1;
  }
  return 0;
}

static int tx_init(struct alias_tx_1160 *tx, size_t alias_pages) {
  flat_pmap syscore_flat;
  flat_pmap source_flat;
  size_t leaf_entries;

  memset(tx, 0, sizeof(*tx));
  if (get_proc_pmap_checked(MINI_SYSCORE_PID, &syscore_flat) ||
      get_proc_pmap_checked(getpid(), &source_flat) ||
      syscore_flat.pm_pml4 == source_flat.pm_pml4)
    return -1;

  tx->syscore_pml4 = syscore_flat.pm_pml4;
  tx->source_pml4 = source_flat.pm_pml4;
  if (alias_pages > SIZE_MAX / (PAGE_SIZE / X86_PAGE_SIZE))
    return -1;
  leaf_entries = alias_pages * (PAGE_SIZE / X86_PAGE_SIZE);
  if (leaf_entries > SIZE_MAX - 1024)
    return -1;
  tx->journal_capacity = leaf_entries + 1024;
  tx->journal = calloc(tx->journal_capacity, sizeof(*tx->journal));
  if (!tx->journal)
    return -1;

  tx->table_capacity = alias_pages / 128 + 16;
  tx->tables = calloc(tx->table_capacity, sizeof(*tx->tables));
  if (!tx->tables) {
    free(tx->journal);
    memset(tx, 0, sizeof(*tx));
    return -1;
  }
  return 0;
}

static int tx_write(struct alias_tx_1160 *tx, uint64_t entry_va,
                    uint64_t new_value) {
  uint64_t old_value = 0;
  uint64_t observed = 0;

  if (tx->journal_count >= tx->journal_capacity ||
      read_entry(entry_va, &old_value))
    return -1;
  tx->journal[tx->journal_count].entry_va = entry_va;
  tx->journal[tx->journal_count].old_value = old_value;
  tx->journal_count++;
  if (write_kernel(entry_va, &new_value, sizeof(new_value)) ||
      read_entry(entry_va, &observed) || observed != new_value)
    return -1;
  return 0;
}

static int tx_alloc_table(struct alias_tx_1160 *tx, uint64_t *pa_out) {
  void *mapping;
  uint64_t pa = 0;

  if (tx->table_count >= tx->table_capacity)
    return -1;
  mapping = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED)
    return -1;
  memset(mapping, 0, PAGE_SIZE);
  if (source_page_pa(tx->source_pml4, mapping, &pa)) {
    munmap(mapping, PAGE_SIZE);
    return -1;
  }
  tx->tables[tx->table_count].mapping = mapping;
  tx->tables[tx->table_count].pa = pa;
  tx->table_count++;
  *pa_out = pa;
  return 0;
}

static int ensure_child_table(struct alias_tx_1160 *tx, uint64_t entry_va,
                              int reject_large, uint64_t *child_pa) {
  uint64_t entry = 0;
  uint64_t pa = 0;

  if (read_entry(entry_va, &entry))
    return -1;
  if (PAGE_P(entry)) {
    if (reject_large && PAGE_PS(entry))
      return -1;
    *child_pa = PAGE_PA(entry);
    return 0;
  }
  if (tx_alloc_table(tx, &pa) ||
      tx_write(tx, entry_va, pa | TABLE_FLAGS))
    return -1;
  *child_pa = pa;
  return 0;
}

static int tx_install_page(struct alias_tx_1160 *tx,
                           const struct alias_page_1160 *page) {
  uint64_t entry_va;
  uint64_t child_pa;

  entry_va = tx->syscore_pml4 + pmap_pml4e_index(page->target_va) * 8;
  if (ensure_child_table(tx, entry_va, 0, &child_pa))
    return -1;
  entry_va = pa_to_dmap(child_pa) + pmap_pdpe_index(page->target_va) * 8;
  if (ensure_child_table(tx, entry_va, 1, &child_pa))
    return -1;
  entry_va = pa_to_dmap(child_pa) + pmap_pde_index(page->target_va) * 8;
  if (ensure_child_table(tx, entry_va, 1, &child_pa))
    return -1;

  entry_va = pa_to_dmap(child_pa) + pmap_pte_index(page->target_va) * 8;
  for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
    uint64_t pte_va = entry_va + (sub / X86_PAGE_SIZE) * 8;
    uint64_t old_pte = 0;
    if (read_entry(pte_va, &old_pte) || PAGE_P(old_pte) ||
        tx_write(tx, pte_va, page->source_pa + sub + TABLE_FLAGS))
      return -1;
  }
  return 0;
}

static int translate_target(const struct alias_tx_1160 *tx, uint64_t va,
                            uint64_t *pa_out) {
  uint64_t pte_va = 0;
  uint64_t pte = 0;
  int absent = 0;

  if (lookup_pte(tx->syscore_pml4, va, &pte_va, &absent) || absent ||
      read_entry(pte_va, &pte) || !PAGE_P(pte))
    return -1;
  *pa_out = PAGE_PA(pte) | (va & (X86_PAGE_SIZE - 1));
  return 0;
}

static int verify_aliases(const struct alias_tx_1160 *tx,
                          const struct alias_page_1160 *pages,
                          size_t page_count) {
  for (size_t i = 0; i < page_count; i++) {
    for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
      uint64_t pa = 0;
      if (translate_target(tx, pages[i].target_va + sub, &pa) ||
          pa != pages[i].source_pa + sub)
        return -1;
    }
  }
  return 0;
}

static int tx_rollback(struct alias_tx_1160 *tx) {
  int failed = 0;

  for (size_t i = tx->journal_count; i > 0; i--) {
    const struct journal_entry_1160 *entry = &tx->journal[i - 1];
    if (write_kernel(entry->entry_va, &entry->old_value,
                     sizeof(entry->old_value)))
      failed = 1;
  }
  for (size_t i = 0; i < tx->journal_count; i++) {
    const struct journal_entry_1160 *entry = &tx->journal[i];
    uint64_t observed = 0;
    if (read_entry(entry->entry_va, &observed) ||
        observed != entry->old_value)
      failed = 1;
  }
  return failed ? -1 : 0;
}

static int verify_targets_absent(const struct alias_tx_1160 *tx,
                                 const struct alias_page_1160 *pages,
                                 size_t page_count) {
  for (size_t i = 0; i < page_count; i++) {
    for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
      uint64_t pte_va = 0;
      uint64_t pte = 0;
      int absent = 0;
      if (lookup_pte(tx->syscore_pml4, pages[i].target_va + sub, &pte_va,
                     &absent))
        return -1;
      if (!absent && (read_entry(pte_va, &pte) || PAGE_P(pte)))
        return -1;
    }
  }
  return 0;
}

static void tx_release_backing(struct alias_tx_1160 *tx) {
  for (size_t i = 0; i < tx->table_count; i++) {
    munmap(tx->tables[i].mapping, PAGE_SIZE);
  }
  free(tx->tables);
  free(tx->journal);
  memset(tx, 0, sizeof(*tx));
}

[[noreturn]] static void hold_after_rollback_failure(void) {
  checkpoint("FATAL rollback verification failed; cold reboot required");
  while (1)
    sleep(30);
}

static int build_alias_plan(const struct linux_info *info, void *bzimage,
                            size_t bzimage_mapping_size, void *initrd,
                            size_t initrd_mapping_size,
                            struct alias_tx_1160 *tx,
                            struct alias_page_1160 **pages_out,
                            size_t *page_count_out, void **info_page_out) {
  size_t bz_pages = bzimage_mapping_size / PAGE_SIZE;
  size_t initrd_pages = initrd_mapping_size / PAGE_SIZE;
  size_t page_count;
  struct alias_page_1160 *pages = NULL;
  void *info_page = MAP_FAILED;
  size_t at = 0;

  if (add_size(1, bz_pages, &page_count) ||
      add_size(page_count, initrd_pages, &page_count) ||
      page_count > SIZE_MAX / sizeof(*pages))
    return -1;
  pages = calloc(page_count, sizeof(*pages));
  if (!pages)
    return -1;

  info_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (info_page == MAP_FAILED) {
    free(pages);
    return -1;
  }
  memset(info_page, 0, PAGE_SIZE);
  memcpy(info_page, info, sizeof(*info));

  pages[at].target_va = info->linux_info;
  pages[at++].source = info_page;
  for (size_t offset = 0; offset < bzimage_mapping_size;
       offset += PAGE_SIZE) {
    pages[at].target_va = info->bzimage + offset;
    pages[at++].source = (const uint8_t *)bzimage + offset;
  }
  for (size_t offset = 0; offset < initrd_mapping_size;
       offset += PAGE_SIZE) {
    pages[at].target_va = info->initrd + offset;
    pages[at++].source = (const uint8_t *)initrd + offset;
  }

  for (size_t i = 0; i < page_count; i++) {
    if (source_page_pa(tx->source_pml4, pages[i].source,
                       &pages[i].source_pa)) {
      munmap(info_page, PAGE_SIZE);
      free(pages);
      return -1;
    }
  }

  *pages_out = pages;
  *page_count_out = page_count;
  *info_page_out = info_page;
  return 0;
}

int stage_linux_aliases_1160(const struct linux_info *info, void *bzimage,
                             size_t bzimage_mapping_size, void *initrd,
                             size_t initrd_mapping_size) {
  struct alias_tx_1160 tx;
  struct alias_page_1160 *pages = NULL;
  size_t page_count = 0;
  size_t combined_mapping = 0;
  void *info_page = MAP_FAILED;
  int writes_started = 0;
  int result = -1;

  memset(&tx, 0, sizeof(tx));
  if (!info || !bzimage || !initrd || retained_staging.active ||
      !bzimage_mapping_size || !initrd_mapping_size ||
      (bzimage_mapping_size & (PAGE_SIZE - 1)) ||
      (initrd_mapping_size & (PAGE_SIZE - 1)) ||
      add_size(bzimage_mapping_size, initrd_mapping_size,
               &combined_mapping) ||
      combined_mapping > MAX_COMBINED_MAPPING ||
      info->linux_info != kernel_cave_linux_info ||
      info->bzimage != kernel_cave_bzImage ||
      info->initrd != info->bzimage + bzimage_mapping_size) {
    checkpoint("REFUSED invalid source/target layout; no writes attempted");
    return -1;
  }

  checkpoint("building checked source plan");
  if (tx_init(&tx, 1 + combined_mapping / PAGE_SIZE)) {
    checkpoint("REFUSED invalid PID-1/current pmap state; no writes attempted");
    goto out;
  }
  if (build_alias_plan(info, bzimage, bzimage_mapping_size, initrd,
                       initrd_mapping_size, &tx, &pages, &page_count,
                       &info_page)) {
    checkpoint("REFUSED source-frame preflight failed; no writes attempted");
    goto out;
  }

  printf("11.60 alias staging: source preflight passed (%zu logical 16-KiB "
         "pages)\n",
         page_count);
  fflush(stdout);

  for (size_t i = 0; i < page_count; i++) {
    if (preflight_target_page(tx.syscore_pml4, pages[i].target_va)) {
      printf("11.60 alias staging: REFUSED target page %zu at 0x%llx before "
             "mutation\n",
             i, (unsigned long long)pages[i].target_va);
      fflush(stdout);
      goto out;
    }
  }
  checkpoint("target range preflight passed");

  checkpoint("installing checked aliases");
  for (size_t i = 0; i < page_count; i++) {
    writes_started = 1;
    if (tx_install_page(&tx, &pages[i])) {
      printf("11.60 alias staging: install failed at page %zu target "
             "0x%llx\n",
             i, (unsigned long long)pages[i].target_va);
      fflush(stdout);
      goto rollback;
    }
  }
  checkpoint("all aliases installed");

  checkpoint("verifying alias PTEs");
  if (verify_aliases(&tx, pages, page_count)) {
    checkpoint("alias verification failed");
    goto rollback;
  }
  printf("11.60 alias staging: all %zu leaf PTEs verified\n",
         page_count * (size_t)(PAGE_SIZE / X86_PAGE_SIZE));
  fflush(stdout);

  retained_staging.bzimage = bzimage;
  retained_staging.bzimage_mapping_size = bzimage_mapping_size;
  retained_staging.initrd = initrd;
  retained_staging.initrd_mapping_size = initrd_mapping_size;
  retained_staging.info_page = info_page;
  retained_staging.tx = tx;
  retained_staging.active = 1;
  checkpoint("PASS; source, info, and page-table backing retained");
  result = 0;
  goto done;

rollback:
  checkpoint("install/verify failed; rolling back");
  if (tx_rollback(&tx) || verify_targets_absent(&tx, pages, page_count))
    hold_after_rollback_failure();
  checkpoint("rollback verified");
  writes_started = 0;

out:
  if (info_page != MAP_FAILED) {
    munmap(info_page, PAGE_SIZE);
  }
  if (writes_started && tx.journal_count != 0) {
    /* All mutation failures must pass through the rollback label. */
    hold_after_rollback_failure();
  }
  tx_release_backing(&tx);

done:
  free(pages);
  return result;
}

#endif
