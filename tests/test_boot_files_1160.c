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

static uint8_t *image;

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
}

static int check(size_t size) { return check_bzimage_1160(image, size, NULL); }

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
  assert(check_bzimage_1160(buf, (size_t)size, &layout) == BZ_OK_1160);
  printf("%s: protocol 0x%x setup %u payload %llu decompress 0x%llx-0x%llx\n",
         path, layout.version, layout.setup_size,
         (unsigned long long)layout.payload_size,
         (unsigned long long)layout.decompress_base,
         (unsigned long long)layout.decompress_end);
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

  run15_header();
  put32(0x238, 255);
  assert(check(RUN15_SIZE) == BZ_CMDLINE_SIZE_1160);

  /* initrd formats. */
  memcpy(initrd, "070701", 6);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  memcpy(initrd, "\x28\xb5\x2f\xfd", 4);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  memcpy(initrd, "\x1f\x8b", 2);
  assert(check_initrd_1160(initrd, sizeof(initrd)) == 0);
  assert(check_initrd_1160(initrd, sizeof(initrd) - 1) != 0);
  memcpy(initrd, "MZ\x00\x00", 4);
  assert(check_initrd_1160(initrd, sizeof(initrd)) != 0);
  memset(initrd, 0, sizeof(initrd));
  assert(check_initrd_1160(initrd, sizeof(initrd)) != 0);

  for (int i = 1; i < argc; i++)
    if (argv[i][0] != '\0')
      check_file(argv[i]);

  free(image);
  printf("boot file checks OK\n");
  return 0;
}
