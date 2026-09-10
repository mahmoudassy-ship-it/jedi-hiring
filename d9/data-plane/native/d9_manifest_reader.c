#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define D9_MANIFEST_BYTES_HARD_MAX 2097152ULL

#ifndef D9_FORCE_OPENAT2_UNAVAILABLE
#define D9_FORCE_OPENAT2_UNAVAILABLE 0
#endif

static void fail(const char *code, int detail) {
  if (detail == 0) {
    (void)fprintf(stderr, "%s\n", code);
  } else {
    (void)fprintf(stderr, "%s:%d\n", code, detail);
  }
  exit(2);
}

static bool safe_relative_path(const char *value) {
  const unsigned char *cursor = (const unsigned char *)value;
  size_t component_length = 0U;
  size_t total_length;

  if (value == NULL) return false;
  total_length = strlen(value);
  if (total_length == 0U || total_length > 240U || value[0] == '/') return false;

  while (*cursor != '\0') {
    const unsigned char byte = *cursor;
    if (byte == '\\' || byte < 0x21U || byte == 0x7fU) return false;
    if (byte == '/') {
      if (component_length == 0U || component_length > 120U) return false;
      if ((component_length == 1U && cursor[-1] == '.') ||
          (component_length == 2U && cursor[-2] == '.' && cursor[-1] == '.')) return false;
      component_length = 0U;
    } else {
      const bool allowed = (byte >= 'A' && byte <= 'Z') ||
                           (byte >= 'a' && byte <= 'z') ||
                           (byte >= '0' && byte <= '9') ||
                           byte == '.' || byte == '_' || byte == '-';
      if (!allowed) return false;
      component_length += 1U;
    }
    cursor += 1;
  }

  if (component_length == 0U || component_length > 120U) return false;
  if ((component_length == 1U && cursor[-1] == '.') ||
      (component_length == 2U && cursor[-2] == '.' && cursor[-1] == '.')) return false;
  return true;
}

static unsigned long long parse_limit(const char *value) {
  char *end = NULL;
  unsigned long long parsed;
  if (value == NULL || value[0] == '\0' || value[0] == '-') fail("INPUT_LIMIT_INVALID", 0);
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0ULL ||
      parsed > D9_MANIFEST_BYTES_HARD_MAX) fail("INPUT_LIMIT_INVALID", 0);
  return parsed;
}

static bool same_identity(const struct stat *before, const struct stat *after) {
  return before->st_dev == after->st_dev &&
         before->st_ino == after->st_ino &&
         before->st_mode == after->st_mode &&
         before->st_nlink == after->st_nlink &&
         before->st_uid == after->st_uid &&
         before->st_gid == after->st_gid &&
         before->st_size == after->st_size &&
         before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
         before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
         before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
         before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static void write_all(int descriptor, const unsigned char *bytes, size_t length) {
  size_t offset = 0U;
  while (offset < length) {
    const ssize_t written = write(descriptor, bytes + offset, length - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) fail("OUTPUT_WRITE_FAILED", errno);
    offset += (size_t)written;
  }
}

int main(int argc, char **argv) {
  const int root_fd = 3;
  struct open_how how;
  struct stat root_status;
  struct stat before;
  struct stat after;
  unsigned long long maximum_bytes;
  unsigned char *bytes = NULL;
  size_t offset = 0U;
  int descriptor;

  if (argc != 3) fail("INPUT_ARGUMENT_INVALID", 0);
  if (!safe_relative_path(argv[1])) fail("INPUT_PATH_INVALID", 0);
  maximum_bytes = parse_limit(argv[2]);
  if (fstat(root_fd, &root_status) != 0 || !S_ISDIR(root_status.st_mode)) {
    fail("INPUT_ROOT_INVALID", errno);
  }

  if (D9_FORCE_OPENAT2_UNAVAILABLE != 0) fail("OPENAT2_UNAVAILABLE", ENOSYS);

  memset(&how, 0, sizeof(how));
  how.flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW;
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
  descriptor = (int)syscall(SYS_openat2, root_fd, argv[1], &how, sizeof(how));
  if (descriptor < 0) {
    if (errno == ENOSYS || errno == E2BIG) fail("OPENAT2_UNAVAILABLE", errno);
    fail("INPUT_OPEN_REJECTED", errno);
  }

  if (fstat(descriptor, &before) != 0) {
    const int saved = errno;
    (void)close(descriptor);
    fail("INPUT_STAT_FAILED", saved);
  }
  if (!S_ISREG(before.st_mode) || before.st_nlink != 1) {
    (void)close(descriptor);
    fail("INPUT_TYPE_REJECTED", 0);
  }
  if (before.st_size <= 0 || (unsigned long long)before.st_size > maximum_bytes) {
    (void)close(descriptor);
    fail("INPUT_SIZE_REJECTED", 0);
  }

  bytes = malloc((size_t)before.st_size);
  if (bytes == NULL) {
    (void)close(descriptor);
    fail("RESOURCE_LIMIT_EXCEEDED", 0);
  }
  while (offset < (size_t)before.st_size) {
    const ssize_t amount = pread(descriptor, bytes + offset,
                                 (size_t)before.st_size - offset, (off_t)offset);
    if (amount < 0 && errno == EINTR) continue;
    if (amount < 0) {
      const int saved = errno;
      free(bytes);
      (void)close(descriptor);
      fail("INPUT_READ_FAILED", saved);
    }
    if (amount == 0) {
      free(bytes);
      (void)close(descriptor);
      fail("INPUT_SHORT_READ", 0);
    }
    offset += (size_t)amount;
  }

  if (fstat(descriptor, &after) != 0 || !same_identity(&before, &after)) {
    const int saved = errno;
    free(bytes);
    (void)close(descriptor);
    fail("INPUT_CHANGED", saved);
  }
  if (close(descriptor) != 0) {
    const int saved = errno;
    free(bytes);
    fail("INPUT_CLOSE_FAILED", saved);
  }

  write_all(STDOUT_FILENO, bytes, (size_t)before.st_size);
  free(bytes);
  return 0;
}
