#include "loader.h"
#include "config.h"
#include "firmware.h"
#include "linux.h"
#include "loader_staging_1160.h"
#include "utils.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

const char *file_paths[] = {
    "/mnt/usb0/",           "/mnt/usb1/",           "/mnt/usb2/",
    "/mnt/usb3/",           "/mnt/usb4/",           "/mnt/usb5/",
    "/mnt/usb6/",           "/mnt/usb7/",           "/mnt/usb0/PS5/Linux/",
    "/mnt/usb1/PS5/Linux/", "/mnt/usb2/PS5/Linux/", "/mnt/usb3/PS5/Linux/",
    "/mnt/usb4/PS5/Linux/", "/mnt/usb5/PS5/Linux/", "/mnt/usb6/PS5/Linux/",
    "/mnt/usb7/PS5/Linux/",
};

static void diagnose_usb_mounts(void) {
  static const char *paths[] = {
      "/mnt",      "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3",
      "/mnt/usb4", "/mnt/usb5", "/mnt/usb6", "/mnt/usb7",
  };

  printf("11.60 USB census: begin\n");
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    errno = 0;
    DIR *dir = opendir(paths[i]);
    if (!dir) {
      printf("[usb] %s unavailable errno=%d\n", paths[i], errno);
      continue;
    }

    printf("[usb] %s open\n", paths[i]);
    struct dirent *ent;
    unsigned count = 0;
    while ((ent = readdir(dir)) != NULL && count < 64) {
      printf("[usb] %s/%s\n", paths[i], ent->d_name);
      count++;
    }
    closedir(dir);
  }
  printf("11.60 USB census: end\n");
  fflush(stdout);
}

long find_and_get_size_of_file(const char *filename, char *found_path);
int find_and_read_file(const char *filename, void *buf, size_t bufsize);

static const char *get_overridden_filename(const char *filename) {
  static int state = 0;
  static char *overrides_start = nullptr;
  static char *overrides_end = nullptr;

  if (state == 0) {
    state = 1;
    char found_path[256];
    ssize_t size = find_and_get_size_of_file("path-override.txt", found_path);
    if (size > 0) {
      overrides_start = malloc(size + 1);
      overrides_end = overrides_start + size + 1;
      if (read_file(found_path, overrides_start, size) == size) {
        state = 2;
        for (char *p = overrides_start; p < overrides_end; p++)
          if (*p == '\n')
            *p = 0;
        // make sure the last string is null-terminated
        overrides_start[size] = 0;
      }
    }
  }

  // overrides not found, or unreadable, or currently looking for it
  if (state == 1)
    return filename;

  size_t needle_len = strlen(filename);
  for (const char *p = overrides_start; p < overrides_end;) {
    size_t haystack_len = strlen(p);
    if (haystack_len > needle_len && !strncmp(p, filename, needle_len) &&
        p[needle_len] == '=')
      return p + needle_len + 1;
    p += haystack_len + 1;
  }

  // haven't found an override, return original filename
  return filename;
}

long find_and_get_size_of_file(const char *filename, char *found_path) {
  char full_path[256];
  struct stat st;

  filename = get_overridden_filename(filename);
  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      strcpy(found_path, full_path);
      return st.st_size;
    }
  }

  return -1;
}

int find_and_read_file(const char *filename, void *buf, size_t bufsize) {
  char full_path[256];
  struct stat st;

  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      return read_file(full_path, buf, bufsize);
    }
  }

  return -1;
}

int read_file(const char *path, void *buf, size_t bufsize) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return fd;
  int r = read(fd, buf, bufsize);
  close(fd);
  return r;
}

#if FW_1160_PORT
#define READ_CHUNK_1160 (1024ULL * 1024ULL)
#define MAX_BZIMAGE_SIZE_1160 (64ULL * 1024ULL * 1024ULL)
#define MAX_INITRD_SIZE_1160 (128ULL * 1024ULL * 1024ULL)
#define VALIDATED_BZIMAGE_SIZE_1160 12702720ULL
#define VALIDATED_INITRD_SIZE_1160 54376639ULL

/* Payload menus only show notify() messages, so the size refusals below are
 * invisible there.  Only the linux-1160-dma-e820-visible target sets this. */
#ifndef PS5_1160_VISIBLE_REFUSALS
#define PS5_1160_VISIBLE_REFUSALS 0
#endif

static int align_mapping_size_1160(size_t size, size_t *aligned) {
  if (size == 0 || size > SIZE_MAX - (PAGE_SIZE - 1))
    return -1;
  *aligned = ALIGN_UP(size, PAGE_SIZE);
  return 0;
}

/* Stage 0 proved this bounded, fully-faulted, chunked read path on 11.60. */
static int read_file_exact_1160(const char *path, void *buf, size_t size) {
  int fd = open(path, O_RDONLY);
  size_t total = 0;

  if (fd < 0)
    return -1;
  while (total < size) {
    size_t remaining = size - total;
    size_t chunk = remaining > READ_CHUNK_1160 ? READ_CHUNK_1160 : remaining;
    ssize_t n = read(fd, (uint8_t *)buf + total, chunk);

    if (n < 0) {
      if (errno == EINTR)
        continue;
      close(fd);
      return -1;
    }
    if (n == 0) {
      close(fd);
      return -1;
    }
    total += (size_t)n;
  }
  return close(fd) == 0 ? 0 : -1;
}
#endif

void trim_newline(char *s) {
  while (*s != '\0') {
    if (*s == '\r' || *s == '\n') {
      *s = '\0';
      break;
    }
    s++;
  }
}

int fetch_linux(struct linux_info *info) {
  char bzimage_path[256];
  char initrd_path[256];

  long bzimage_file_size = find_and_get_size_of_file("bzImage", bzimage_path);
  if (bzimage_file_size < 0) {
    if (fw == 0x1160)
      diagnose_usb_mounts();
    notify("File bzImage not found at default paths - Aborting\n");
    return -1;
  }
  size_t bzimage_size = (size_t)bzimage_file_size;
  size_t bzimage_mapping_size;

#if FW_1160_PORT
  if (bzimage_size != VALIDATED_BZIMAGE_SIZE_1160) {
#if PS5_1160_VISIBLE_REFUSALS
    notify("11.60 loader refused bzImage: %zu bytes, needs exactly %llu. "
           "Use the 11.60 image.\n",
           bzimage_size, (unsigned long long)VALIDATED_BZIMAGE_SIZE_1160);
    fflush(stdout);
#else
    printf("11.60 loader REFUSED bzImage size %zu; validated size is %llu\n",
           bzimage_size, (unsigned long long)VALIDATED_BZIMAGE_SIZE_1160);
    fflush(stdout);
#endif
    return -1;
  }
  if (bzimage_size > MAX_BZIMAGE_SIZE_1160 ||
      align_mapping_size_1160(bzimage_size, &bzimage_mapping_size)) {
    notify("11.60 loader refused invalid bzImage size.\n");
    return -1;
  }
#else
  bzimage_mapping_size = ALIGN_UP(bzimage_size, PAGE_SIZE);
#endif

  void *bzimage =
      mmap(NULL, bzimage_mapping_size, PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (bzimage == MAP_FAILED) {
    notify("[-] Error could not allocate bzimage.\n");
    return -1;
  }

#if FW_1160_PORT
  /* Commit and zero the aligned tail before resolving any source frames. */
  memset(bzimage, 0, bzimage_mapping_size);
  if (read_file_exact_1160(bzimage_path, bzimage, bzimage_size)) {
    notify("Something went wrong while reading bzImage - Aborting\n");
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
  printf("11.60 loader checkpoint: bzImage read complete (%zu bytes)\n",
         bzimage_size);
  fflush(stdout);
#else
  int bytes_read =
      read_file(bzimage_path, bzimage, bzimage_mapping_size);
  if (bytes_read < 0) {
    notify("Something went wrong while reading bzImage - Aborting\n");
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
  bzimage_size = (size_t)bytes_read;
#endif

  long initrd_file_size =
      find_and_get_size_of_file("initrd.img", initrd_path);
  if (initrd_file_size < 0) {
    notify("File initrd.img not found at default paths - Aborting\n");
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
  size_t initrd_size = (size_t)initrd_file_size;
  size_t initrd_mapping_size;

#if FW_1160_PORT
  if (initrd_size != VALIDATED_INITRD_SIZE_1160) {
#if PS5_1160_VISIBLE_REFUSALS
    notify("11.60 loader refused initrd.img: %zu bytes, needs exactly %llu. "
           "Use the 11.60 image.\n",
           initrd_size, (unsigned long long)VALIDATED_INITRD_SIZE_1160);
    fflush(stdout);
#else
    printf("11.60 loader REFUSED initrd size %zu; validated size is %llu\n",
           initrd_size, (unsigned long long)VALIDATED_INITRD_SIZE_1160);
    fflush(stdout);
#endif
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
  if (initrd_size > MAX_INITRD_SIZE_1160 ||
      align_mapping_size_1160(initrd_size, &initrd_mapping_size)) {
    notify("11.60 loader refused invalid initrd size.\n");
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
#else
  initrd_mapping_size = ALIGN_UP(initrd_size, PAGE_SIZE);
#endif

  void *initrd =
      mmap(NULL, initrd_mapping_size, PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (initrd == MAP_FAILED) {
    notify("[-] Error could not allocate initrd.\n");
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }

#if FW_1160_PORT
  memset(initrd, 0, initrd_mapping_size);
  if (read_file_exact_1160(initrd_path, initrd, initrd_size)) {
    notify("Something went wrong while reading initrd - Aborting\n");
    munmap(initrd, initrd_mapping_size);
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
  printf("11.60 loader checkpoint: initrd read complete (%zu bytes)\n",
         initrd_size);
  fflush(stdout);
#else
  bytes_read =
      read_file(initrd_path, initrd, initrd_mapping_size);
  if (bytes_read < 0) {
    notify("Something went wrong while reading initrd - Aborting\n");
    munmap(initrd, initrd_mapping_size);
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
  initrd_size = (size_t)bytes_read;
#endif

  if (dump_device_firmwares(initrd_path) < 0) {
    notify(
        "Something went wrong while dumping device firmwares - Continuing\n");
  }

  size_t vram_size;
  char buf_vram[16] = {};
  int ret = find_and_read_file("vram.txt", buf_vram, sizeof(buf_vram) - 1);
  if (ret < 0) {
    printf(
        "File vram.txt not found at default paths - Using static fallback\n");
    vram_size = VRAM_SIZE;
  } else {
    trim_newline(buf_vram);
    vram_size = strtoull(buf_vram, NULL, 16);
    if (vram_size == 0) {
      printf("Seems like the configured vram value is wrong - Using static "
             "fallback\n");
      vram_size = VRAM_SIZE;
    }
  }

  char cmdline[2048] = {};
  ret = find_and_read_file("cmdline.txt", cmdline, sizeof(cmdline) - 1);
  if (ret < 0) {
    printf("File cmdline.txt not found at default paths - Using static "
           "fallback\n");
    strcpy(cmdline, CMD_LINE);
  } else {
    trim_newline(cmdline);
  }

  info->linux_info = kernel_cave_linux_info;
  info->bzimage = kernel_cave_bzImage;
  info->bzimage_size = bzimage_size;
  info->initrd = kernel_cave_bzImage + ALIGN_UP(bzimage_size, PAGE_SIZE);
  info->initrd_size = initrd_size;
  info->vram_size = vram_size;
  info->kit_type = (int)get_kit_type();
  strcpy(info->cmdline, cmdline);

#if FW_1160_PORT
  /*
   * Keep Sonic's pre-suspend PID-1 aliases, but use the checked Stage-1A/1B
   * allocator/walker that was exercised on this exact 11.60 console instead
   * of the upstream unchecked install_page_syscore helper.
   */
  if (stage_linux_aliases_1160(info, bzimage, bzimage_mapping_size, initrd,
                               initrd_mapping_size)) {
    notify("11.60 checked Linux alias staging failed.\n");
    munmap(initrd, initrd_mapping_size);
    munmap(bzimage, bzimage_mapping_size);
    return -1;
  }
  return 0;
#else
  uint64_t page = alloc_page();
  kwrite(pa_to_dmap(page), info, sizeof(struct linux_info));
  install_page_syscore(kernel_cave_linux_info, page, 0);

  for (int i = 0; i < bzimage_size; i += PAGE_SIZE) {
    install_page_syscore(info->bzimage + i,
                         vtophys_user((uintptr_t)bzimage + i), 0);
  }

  for (int i = 0; i < initrd_size; i += PAGE_SIZE) {
    install_page_syscore(info->initrd + i, vtophys_user((uintptr_t)initrd + i),
                         0);
  }

  return 0;
#endif
}
