#ifndef BOOT_FILES_1160_H
#define BOOT_FILES_1160_H

/*
 * Boot file checks for the bounded 11.60 builds (linux-1160-dma-e820-bounded
 * and linux-1160-dma-e820-bounded-wifi).  The other 11.60 builds keep the
 * exact Run 15 sizes and never include this.
 *
 * The limits follow what the inner HV does in shellcode_hv/boot_linux.c: it
 * copies the setup header out of the staged bzImage, skips
 * (setup_sects + 1) * 512 bytes of setup, copies syssize * 16 bytes to
 * 0x100000 and calls the 64-bit entry at 0x100000 + 0x200 with boot_params at
 * 0x10000 and the command line at 0x20000.  The decompressor then moves itself
 * to the end of [base, base + init_size), where base is pref_address for the
 * kernels used so far (0x1000000).  The wake blob stages the initrd above
 * 4 GiB, right after the bzImage at 0x100009000.
 */

#include <stddef.h>
#include <stdint.h>

/* End of kernel_info_offset, the last field of a 2.15 setup header. */
#define BZ_HEADER_END_1160 0x26cU
#define BZ_MIN_VERSION_1160 0x020fU
#define BZ_MAX_SETUP_SECTS_1160 64U
/* kernel_pa in shellcode_hv/boot_linux.c. */
#define BZ_LOAD_PA_1160 0x100000ULL
/* Low RAM ends here in the Run 15 map; the DMA map reserves 16 MiB..1 GiB. */
#define BZ_DECOMPRESS_LIMIT_1160 0x3fffc000ULL
#define BZ_MIN_ALIGN_1160 0x200000U
#define BZ_MAX_ALIGN_1160 0x1000000U
/* The loader reads at most 2047 bytes of cmdline.txt. */
#define BZ_MIN_CMDLINE_SIZE_1160 2047U
#define INITRD_MIN_SIZE_1160 512U
/* MAX_COMBINED_MAPPING in source/loader_staging_1160.c: bzImage plus initrd,
 * each rounded up to whole 16-KiB pages. */
#define MAX_STAGED_BOOT_FILES_1160 (160ULL * 1024ULL * 1024ULL)

#define BZ_LOADED_HIGH_1160 0x01U
#define BZ_XLF_KERNEL_64_1160 0x0001U
#define BZ_XLF_CAN_BE_LOADED_ABOVE_4G_1160 0x0002U

enum bz_refusal_1160 {
  BZ_OK_1160 = 0,
  BZ_SHORT_1160 = 1,
  BZ_BOOT_FLAG_1160 = 2,
  BZ_MAGIC_1160 = 3,
  BZ_VERSION_1160 = 4,
  BZ_SETUP_SECTS_1160 = 5,
  BZ_SYSSIZE_1160 = 6,
  BZ_LOADFLAGS_1160 = 7,
  BZ_RELOCATABLE_1160 = 8,
  BZ_ALIGNMENT_1160 = 9,
  BZ_PREF_ADDRESS_1160 = 10,
  BZ_INIT_SIZE_1160 = 11,
  BZ_CMDLINE_SIZE_1160 = 12,
};

struct bz_layout_1160 {
  uint16_t version;
  uint16_t xloadflags;
  uint32_t setup_size;
  uint64_t payload_size;  /* syssize * 16, copied to BZ_LOAD_PA_1160 */
  uint64_t decompress_base;
  uint64_t decompress_end; /* decompress_base + init_size */
};

static inline uint16_t bz_u16_1160(const uint8_t *p) {
  return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t bz_u32_1160(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static inline uint64_t bz_u64_1160(const uint8_t *p) {
  return (uint64_t)bz_u32_1160(p) | ((uint64_t)bz_u32_1160(p + 4) << 32);
}

/* Returns BZ_OK_1160 or the first check that failed. */
static inline int check_bzimage_1160(const uint8_t *image, size_t size,
                                     struct bz_layout_1160 *out) {
  struct bz_layout_1160 layout = {0};
  uint32_t setup_sects;
  uint32_t syssize;
  uint32_t alignment;
  uint32_t init_size;
  uint64_t pref_address;
  uint64_t aligned_load;

  if (image == NULL || size < BZ_HEADER_END_1160)
    return BZ_SHORT_1160;
  if (bz_u16_1160(image + 0x1fe) != 0xaa55U)
    return BZ_BOOT_FLAG_1160;
  if (bz_u32_1160(image + 0x202) != 0x53726448U) /* "HdrS" */
    return BZ_MAGIC_1160;
  layout.version = bz_u16_1160(image + 0x206);
  if (layout.version < BZ_MIN_VERSION_1160)
    return BZ_VERSION_1160;

  /* The protocol reads 0 as 4, but the inner HV computes (0 + 1) * 512. */
  setup_sects = image[0x1f1];
  if (setup_sects == 0 || setup_sects > BZ_MAX_SETUP_SECTS_1160)
    return BZ_SETUP_SECTS_1160;
  layout.setup_size = (setup_sects + 1U) * 512U;
  if (layout.setup_size > size)
    return BZ_SETUP_SECTS_1160;

  /* The inner HV copies syssize * 16 bytes; they must all be in the file. */
  syssize = bz_u32_1160(image + 0x1f4);
  layout.payload_size = (uint64_t)syssize * 16U;
  if (syssize == 0 || layout.payload_size > size - layout.setup_size)
    return BZ_SYSSIZE_1160;

  layout.xloadflags = bz_u16_1160(image + 0x236);
  if ((image[0x211] & BZ_LOADED_HIGH_1160) == 0 ||
      (layout.xloadflags & BZ_XLF_KERNEL_64_1160) == 0 ||
      (layout.xloadflags & BZ_XLF_CAN_BE_LOADED_ABOVE_4G_1160) == 0)
    return BZ_LOADFLAGS_1160;

  /* KASLR has to be able to move the kernel out of the DMA reservation. */
  if (image[0x234] != 1)
    return BZ_RELOCATABLE_1160;

  alignment = bz_u32_1160(image + 0x230);
  if (alignment < BZ_MIN_ALIGN_1160 || alignment > BZ_MAX_ALIGN_1160 ||
      (alignment & (alignment - 1U)) != 0)
    return BZ_ALIGNMENT_1160;

  /*
   * head_64.S: base = ALIGN_UP(load address, kernel_alignment), raised to
   * LOAD_PHYSICAL_ADDR (= pref_address) when lower.  Keep the loaded image
   * below base, as in Runs 15 to 19 (0xd18400 < 0x1000000).
   */
  pref_address = bz_u64_1160(image + 0x258);
  if ((pref_address & (alignment - 1U)) != 0)
    return BZ_PREF_ADDRESS_1160;
  aligned_load = (BZ_LOAD_PA_1160 + alignment - 1U) & ~((uint64_t)alignment - 1U);
  layout.decompress_base =
      aligned_load > pref_address ? aligned_load : pref_address;
  if (BZ_LOAD_PA_1160 + layout.payload_size > layout.decompress_base)
    return BZ_PREF_ADDRESS_1160;

  init_size = bz_u32_1160(image + 0x260);
  layout.decompress_end = layout.decompress_base + init_size;
  if (init_size < layout.payload_size ||
      layout.decompress_end > BZ_DECOMPRESS_LIMIT_1160)
    return BZ_INIT_SIZE_1160;

  if (bz_u32_1160(image + 0x238) < BZ_MIN_CMDLINE_SIZE_1160)
    return BZ_CMDLINE_SIZE_1160;

  if (out != NULL)
    *out = layout;
  return BZ_OK_1160;
}

/* A cpio archive or one of the kernel's initramfs decompressors. */
static inline int check_initrd_1160(const uint8_t *initrd, size_t size) {
  static const struct {
    uint8_t len;
    uint8_t bytes[6];
  } magics[] = {
      {5, {'0', '7', '0', '7', '0'}},            /* newc cpio (070701/2) */
      {4, {0x28, 0xb5, 0x2f, 0xfd}},             /* zstd */
      {2, {0x1f, 0x8b}},                         /* gzip */
      {6, {0xfd, '7', 'z', 'X', 'Z', 0x00}},     /* xz */
      {4, {0x02, 0x21, 0x4c, 0x18}},             /* lz4 legacy */
      {3, {0x5d, 0x00, 0x00}},                   /* lzma */
      {3, {'B', 'Z', 'h'}},                      /* bzip2 */
      {4, {0x89, 'L', 'Z', 'O'}},                /* lzo */
  };

  if (initrd == NULL || size < INITRD_MIN_SIZE_1160)
    return -1;
  for (size_t i = 0; i < sizeof(magics) / sizeof(magics[0]); i++) {
    size_t n = magics[i].len;
    size_t j = 0;
    while (j < n && initrd[j] == magics[i].bytes[j])
      j++;
    if (j == n)
      return 0;
  }
  return -1;
}

#endif
