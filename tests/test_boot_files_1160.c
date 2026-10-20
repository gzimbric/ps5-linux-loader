#include "../include/boot_files_1160.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Header fields of the Run 15 7.1.7 bzImage (11280a8f..., 12,702,720 bytes). */
#define RUN15_SIZE 12702720U
#define RUN15_SETUP_SECTS 39U
#define RUN15_SYSSIZE 792640U
#define RUN15_INIT_SIZE 0x2ac9000U
/* Where the synthetic image keeps kaslr.o's message, inside the payload. */
#define KASLR_AT (20480U + 0x1000U)
#define KASLR_LEN (sizeof(BZ_KASLR_MESSAGE_1160) - 1U)

static uint8_t *image;

static void set32(uint8_t *buf, size_t off, uint32_t v) {
  for (int i = 0; i < 4; i++)
    buf[off + i] = (uint8_t)(v >> (8 * i));
}

static uint32_t get32(const uint8_t *buf, size_t off) {
  return (uint32_t)buf[off] | ((uint32_t)buf[off + 1] << 8) |
         ((uint32_t)buf[off + 2] << 16) | ((uint32_t)buf[off + 3] << 24);
}

static void put16(size_t off, uint16_t v) {
  image[off] = (uint8_t)v;
  image[off + 1] = (uint8_t)(v >> 8);
}

static void put32(size_t off, uint32_t v) {
  put16(off, (uint16_t)v);
  put16(off + 2, (uint16_t)(v >> 16));
}

static void put64(size_t off, uint64_t v) {
  put32(off, (uint32_t)v);
  put32(off + 4, (uint32_t)(v >> 32));
}

static void run15_header(void) {
  memset(image, 0, BZ_HEADER_END_1160);
  image[0x1f1] = RUN15_SETUP_SECTS;
  put32(0x1f4, RUN15_SYSSIZE);
  put16(0x1fe, 0xaa55);
  put32(0x202, 0x53726448);
  put16(0x206, 0x020f);
  image[0x211] = 0x01;
  put32(0x230, 0x200000);
  image[0x234] = 1;
  image[0x235] = 21;
  put16(0x236, 0x7f);
  put32(0x238, 2047);
  put64(0x258, 0x1000000);
  put32(0x260, RUN15_INIT_SIZE);
  memcpy(image + KASLR_AT, BZ_KASLR_MESSAGE_1160, KASLR_LEN);
}

static int check(size_t size) { return check_bzimage_1160(image, size, NULL); }

/*
 * The header fields of the two kernels booted or built so far, and where
 * kaslr.o's message sits in each file, so CI runs the real-kernel checks on
 * their layout without the kernels.  PS5_1160_TEST_BZIMAGE runs them on the
 * files themselves.
 */
struct kernel_1160 {
  const char *name;
  uint32_t size;
  uint8_t setup_sects;
  uint32_t syssize;
  uint32_t init_size;
  uint32_t kaslr_at;
  uint64_t decompress_end;
};

static const struct kernel_1160 kernels[] = {
    {"Run 15 7.1.7 layout (11280a8f...)", RUN15_SIZE, RUN15_SETUP_SECTS,
     RUN15_SYSSIZE, RUN15_INIT_SIZE, 12695416U, 0x3ac9000U},
    {"CachyOS 7.3 layout (2f7999fe...)", 11617280U, 39U, 724800U, 0x26c5000U,
     11609736U, 0x36c5000U},
};

static uint8_t *find(uint8_t *buf, size_t size, const char *text) {
  size_t n = strlen(text);
  for (size_t i = 0; i + n <= size; i++)
    if (memcmp(buf + i, text, n) == 0)
      return buf + i;
  return NULL;
}

/* A kernel passes, and the same kernel without kaslr.o's message, or with a
 * setup_data list, is refused.  buf is left as it was. */
static void check_kernel(const char *name, uint8_t *buf, size_t size,
                         struct bz_layout_1160 *layout) {
  uint8_t *message;

  assert(check_bzimage_1160(buf, size, layout) == BZ_OK_1160);
  printf("%s: protocol 0x%x setup %u payload %llu decompress 0x%llx-0x%llx\n",
         name, layout->version, layout->setup_size,
         (unsigned long long)layout->payload_size,
         (unsigned long long)layout->decompress_base,
         (unsigned long long)layout->decompress_end);

  message = find(buf, size, BZ_KASLR_MESSAGE_1160);
  assert(message != NULL);
  message[0] = 0;
  assert(check_bzimage_1160(buf, size, NULL) == BZ_KASLR_1160);
  message[0] = (uint8_t)BZ_KASLR_MESSAGE_1160[0];
  buf[0x250] = 1;
  assert(check_bzimage_1160(buf, size, NULL) == BZ_SETUP_DATA_1160);
  buf[0x250] = 0;
}

static void check_layout(const struct kernel_1160 *k) {
  struct bz_layout_1160 layout;
  uint8_t *buf = calloc(1, k->size);

  assert(buf != NULL);
  memcpy(buf, image, BZ_HEADER_END_1160);
  buf[0x1f1] = k->setup_sects;
  set32(buf, 0x1f4, k->syssize);
  set32(buf, 0x260, k->init_size);
  assert(k->kaslr_at + KASLR_LEN <= k->size);
  memcpy(buf + k->kaslr_at, BZ_KASLR_MESSAGE_1160, KASLR_LEN);
  check_kernel(k->name, buf, k->size, &layout);
  assert(layout.setup_size == (k->setup_sects + 1U) * 512U);
  assert(layout.payload_size == (uint64_t)k->syssize * 16U);
  assert(layout.decompress_base == 0x1000000);
  assert(layout.decompress_end == k->decompress_end);
  /* kaslr.o's message is in the last few KiB of the payload. */
  assert(layout.payload_size + layout.setup_size - k->kaslr_at < 0x4000);
  free(buf);
}

static void check_file(const char *path) {
  FILE *f = fopen(path, "rb");
  struct bz_layout_1160 layout;
  long size;
  uint8_t *buf;

  assert(f != NULL);
  assert(fseek(f, 0, SEEK_END) == 0);
  size = ftell(f);
  assert(size > 0);
  rewind(f);
  buf = malloc((size_t)size);
  assert(buf != NULL);
  assert(fread(buf, 1, (size_t)size, f) == (size_t)size);
  fclose(f);
  check_kernel(path, buf, (size_t)size, &layout);

  /* Keep the CI layouts above in step with the real files. */
  for (size_t i = 0; i < sizeof(kernels) / sizeof(kernels[0]); i++) {
    const struct kernel_1160 *k = &kernels[i];
    if (k->size != (size_t)size)
      continue;
    assert(buf[0x1f1] == k->setup_sects);
    assert(get32(buf, 0x1f4) == k->syssize);
    assert(get32(buf, 0x260) == k->init_size);
    assert(find(buf, (size_t)size, BZ_KASLR_MESSAGE_1160) == buf + k->kaslr_at);
    printf("%s matches the %s\n", path, k->name);
  }
  free(buf);
}

int main(int argc, char **argv) {
  struct bz_layout_1160 layout;
  uint8_t initrd[INITRD_MIN_SIZE_1160] = {0};

  image = calloc(1, RUN15_SIZE);
  assert(image != NULL);

  run15_header();
  assert(check_bzimage_1160(image, RUN15_SIZE, &layout) == BZ_OK_1160);
  assert(layout.setup_size == 20480);
  assert(layout.payload_size == 12682240);
  assert(layout.decompress_base == 0x1000000);
  assert(layout.decompress_end == 0x3ac9000);
  for (size_t i = 0; i < sizeof(kernels) / sizeof(kernels[0]); i++)
    check_layout(&kernels[i]);

  /* Too short, wrong signatures, old protocol. */
  assert(check(BZ_HEADER_END_1160 - 1) == BZ_SHORT_1160);
  put16(0x1fe, 0x55aa);
  assert(check(RUN15_SIZE) == BZ_BOOT_FLAG_1160);
  run15_header();
  put32(0x202, 0x53726449);
  assert(check(RUN15_SIZE) == BZ_MAGIC_1160);
  run15_header();
  put16(0x206, 0x020e);
  assert(check(RUN15_SIZE) == BZ_VERSION_1160);

  /* setup_sects 0 means 4 to the protocol but 1 sector to the inner HV. */
  run15_header();
  image[0x1f1] = 0;
  assert(check(RUN15_SIZE) == BZ_SETUP_SECTS_1160);
  run15_header();
  image[0x1f1] = BZ_MAX_SETUP_SECTS_1160 + 1;
  assert(check(RUN15_SIZE) == BZ_SETUP_SECTS_1160);

  /* The payload must be inside the file. */
  run15_header();
  assert(check(RUN15_SIZE - 1) == BZ_SYSSIZE_1160);
  put32(0x1f4, 0);
  assert(check(RUN15_SIZE) == BZ_SYSSIZE_1160);

  /* 64-bit entry, initrd above 4 GiB, protected-mode code at 1 MiB. */
  run15_header();
  put16(0x236, 0x7e);
  assert(check(RUN15_SIZE) == BZ_LOADFLAGS_1160);
  run15_header();
  put16(0x236, 0x7d);
  assert(check(RUN15_SIZE) == BZ_LOADFLAGS_1160);
  run15_header();
  image[0x211] = 0;
  assert(check(RUN15_SIZE) == BZ_LOADFLAGS_1160);

  run15_header();
  image[0x234] = 0;
  assert(check(RUN15_SIZE) == BZ_RELOCATABLE_1160);

  run15_header();
  put32(0x230, 0x300000);
  assert(check(RUN15_SIZE) == BZ_ALIGNMENT_1160);
  run15_header();
  put32(0x230, 0x100000);
  assert(check(RUN15_SIZE) == BZ_ALIGNMENT_1160);

  /* A 16 MiB alignment still decompresses at pref_address. */
  run15_header();
  put32(0x230, 0x1000000);
  assert(check_bzimage_1160(image, RUN15_SIZE, &layout) == BZ_OK_1160);
  assert(layout.decompress_base == 0x1000000);

  /* The loaded payload must end below the decompression base: 15 MiB. */
  run15_header();
  put64(0x258, 0x800000);
  assert(check(RUN15_SIZE) == BZ_PREF_ADDRESS_1160);
  run15_header();
  put64(0x258, 0x1200000);
  assert(check(RUN15_SIZE) == BZ_OK_1160);
  put64(0x258, 0x1100000);
  assert(check(RUN15_SIZE) == BZ_PREF_ADDRESS_1160);
  {
    size_t big = 20480 + 0xf00000;
    uint8_t *grown = realloc(image, big + 16);
    assert(grown != NULL);
    image = grown;
    run15_header();
    put32(0x1f4, 0xf00000 / 16);
    put32(0x260, 0x4000000);
    assert(check(big) == BZ_OK_1160);
    put32(0x1f4, 0xf00000 / 16 + 1);
    assert(check(big + 16) == BZ_PREF_ADDRESS_1160);
  }

  /* Decompression has to stay below the end of low RAM in the Run 15 map. */
  run15_header();
  put32(0x260, 0x3effc000);
  assert(check(RUN15_SIZE) == BZ_OK_1160);
  put32(0x260, 0x3effc000 + 0x1000);
  assert(check(RUN15_SIZE) == BZ_INIT_SIZE_1160);
  put32(0x260, 0x100000);
  assert(check(RUN15_SIZE) == BZ_INIT_SIZE_1160);

  /* A pref_address past the limit is refused before base + init_size can
   * wrap. */
  run15_header();
  put32(0x230, 0x1000000);
  put64(0x258, 0xffffffffff000000ULL);
  put32(0x260, 0x2000000);
  assert(check(RUN15_SIZE) == BZ_PREF_ADDRESS_1160);
  run15_header();
  put64(0x258, 0x40000000);
  assert(check(RUN15_SIZE) == BZ_PREF_ADDRESS_1160);

  run15_header();
  put32(0x238, 255);
  assert(check(RUN15_SIZE) == BZ_CMDLINE_SIZE_1160);

  /* kaslr.o's message has to be inside the payload the inner HV loads. */
  run15_header();
  memset(image + KASLR_AT, 0, KASLR_LEN);
  assert(check(RUN15_SIZE) == BZ_KASLR_1160);
  memcpy(image + RUN15_SIZE - KASLR_LEN, BZ_KASLR_MESSAGE_1160, KASLR_LEN);
  assert(check(RUN15_SIZE) == BZ_OK_1160);
  put32(0x1f4, RUN15_SYSSIZE - 1);
  assert(check(RUN15_SIZE) == BZ_KASLR_1160);
  memset(image + RUN15_SIZE - KASLR_LEN, 0, KASLR_LEN);

  run15_header();
  put64(0x250, 0xdeadbeef000ULL);
  assert(check(RUN15_SIZE) == BZ_SETUP_DATA_1160);

  /* initrd formats.  The kernel rejects odc cpio (070707). */
  memcpy(initrd, "070701", 6);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  memcpy(initrd, "070702", 6);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  memcpy(initrd, "070707", 6);
  assert(check_initrd_1160(initrd, sizeof(initrd)) != 0);
  /* Leading NULs are skipped; cpio has to start at a multiple of 4. */
  memset(initrd, 0, sizeof(initrd));
  memcpy(initrd + 4, "070701", 6);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  memset(initrd, 0, sizeof(initrd));
  memcpy(initrd + 2, "070701", 6);
  assert(check_initrd_1160(initrd, sizeof(initrd)) != 0);
  memset(initrd, 0, sizeof(initrd));
  memcpy(initrd + 3, "\x1f\x8b", 2);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  memset(initrd, 0, sizeof(initrd));
  memcpy(initrd + sizeof(initrd) - 5, "07070", 5);
  assert(check_initrd_1160(initrd, sizeof(initrd)) != 0);
  memset(initrd, 0, sizeof(initrd));
  memcpy(initrd, "\x28\xb5\x2f\xfd", 4);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  memcpy(initrd, "\x1f\x8b", 2);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  assert(check_initrd_1160(initrd, sizeof(initrd) - 1) != 0);
  memcpy(initrd, "MZ\x00\x00", 4);
  assert(check_initrd_1160(initrd, sizeof(initrd)) != 0);
  memset(initrd, 0, sizeof(initrd));
  assert(check_initrd_1160(initrd, sizeof(initrd)) != 0);

  /* vram.txt: 16 MiB units, below the HV stacks. */
  assert(MAX_VRAM_SIZE_1160 == 0x35f000000ULL);
  assert(check_vram_size_1160(0x20000000) == 0);
  assert(check_vram_size_1160(0x1000000) == 0);
  assert(check_vram_size_1160(MAX_VRAM_SIZE_1160) == 0);
  assert(check_vram_size_1160(MAX_VRAM_SIZE_1160 + 0x1000000) != 0);
  assert(check_vram_size_1160(0x20000001) != 0);
  assert(check_vram_size_1160(0x800000) != 0);
  assert(check_vram_size_1160(0) != 0);

  /* cmdline.txt options that can turn KASLR off or redefine RAM. */
  assert(cmdline_has_option_1160("mem=1G", "mem="));
  assert(cmdline_has_option_1160("root=LABEL=x mem=1G rw", "mem="));
  assert(cmdline_has_option_1160("rw\tmemmap=1G$0x1000000", "memmap="));
  assert(cmdline_has_option_1160("rw \"mem=512M\"", "mem="));
  assert(!cmdline_has_option_1160("memmap=1G!4G", "mem="));
  assert(!cmdline_has_option_1160("foo.mem=1 nomem=2 memtest=1", "mem="));
  assert(!cmdline_has_option_1160("foo.memmap=1 memmapx=1", "memmap="));
  assert(!cmdline_has_option_1160("", "mem="));
  assert(!cmdline_has_option_1160(
      "root=LABEL=__DISTRO__ rw rootwait console=ttyTitania0 console=tty0 "
      "video=DP-1:1920x1080@60 mitigations=off idle=halt preempt=full",
      "mem="));

  /* The kernel splits options at 0xa0, so the option check misses these;
   * any byte above 0x7f is refused instead. */
  assert(!cmdline_has_option_1160("quiet\xc2\xa0mem=1G", "mem="));
  assert(!cmdline_has_option_1160("quiet\xa0memmap=1G$16M", "memmap="));
  assert(cmdline_has_non_ascii_1160("quiet\xc2\xa0mem=1G"));
  assert(cmdline_has_non_ascii_1160("quiet\xa0memmap=1G$16M"));
  assert(cmdline_has_non_ascii_1160("\x80"));
  assert(cmdline_has_non_ascii_1160("rw \xff"));
  assert(!cmdline_has_non_ascii_1160(""));
  assert(!cmdline_has_non_ascii_1160("rw\t\x7f~"));
  assert(!cmdline_has_non_ascii_1160(
      "root=LABEL=__DISTRO__ rw rootwait console=ttyTitania0 console=tty0 "
      "video=DP-1:1920x1080@60 mitigations=off idle=halt preempt=full"));

  for (int i = 1; i < argc; i++)
    if (argv[i][0] != '\0')
      check_file(argv[i]);

  free(image);
  printf("boot file checks OK\n");
  return 0;
}
