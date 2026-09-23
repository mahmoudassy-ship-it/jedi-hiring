#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool safe_part(const char *value) {
  size_t length = strlen(value);
  if (length == 0 || length > 120 || strcmp(value, ".") == 0 || strcmp(value, "..") == 0) return false;
  for (size_t i = 0; i < length; i++) {
    char c = value[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
  }
  return true;
}

static int open_directory(int parent, const char *name) {
  int descriptor = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) return -1;
  struct stat status;
  if (fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode) || status.st_nlink < 2 ||
      (status.st_mode & 0022) != 0 || (status.st_uid != 0 && status.st_uid != geteuid())) {
    close(descriptor); errno = EPERM; return -1;
  }
  return descriptor;
}

int main(int argc, char **argv) {
  if (argc != 12 || (strcmp(argv[1], "unlink") != 0 && strcmp(argv[1], "sync-parent") != 0 && strcmp(argv[1], "verify-absent") != 0)) return 64;
  const char *hash = argv[3];
  if (strlen(hash) != 64) return 64;
  for (size_t i = 0; i < 64; i++) if (!((hash[i] >= '0' && hash[i] <= '9') || (hash[i] >= 'a' && hash[i] <= 'f'))) return 64;
  char prefix[3] = { hash[0], hash[1], '\0' };
  if (!safe_part(prefix) || !safe_part(hash)) return 64;
  char *end = NULL;
  errno = 0; uintmax_t expected_dev = strtoumax(argv[4], &end, 10); if (errno || *end) return 64;
  errno = 0; uintmax_t expected_ino = strtoumax(argv[5], &end, 10); if (errno || *end) return 64;
  errno = 0; uintmax_t expected_size = strtoumax(argv[6], &end, 10); if (errno || *end) return 64;
  errno = 0; uintmax_t expected_root_dev = strtoumax(argv[7], &end, 10); if (errno || *end) return 64;
  errno = 0; uintmax_t expected_root_ino = strtoumax(argv[8], &end, 10); if (errno || *end) return 64;
  errno = 0; uintmax_t expected_parent_dev = strtoumax(argv[9], &end, 10); if (errno || *end) return 64;
  errno = 0; uintmax_t expected_parent_ino = strtoumax(argv[10], &end, 10); if (errno || *end) return 64;
  const char *nonce = argv[11]; if (strlen(nonce) != 64) return 64;

  errno = 0; long inherited_root = strtol(argv[2], &end, 10); if (errno || *end || inherited_root < 0 || inherited_root > 1024) return 64;
  int root = fcntl((int)inherited_root, F_DUPFD_CLOEXEC, 5);
  if (root < 0) return 65;
  struct stat root_status;
  if (fstat(root, &root_status) != 0 || (uintmax_t)root_status.st_dev != expected_root_dev || (uintmax_t)root_status.st_ino != expected_root_ino) { close(root); return 65; }
  int objects = open_directory(root, "objects");
  int algorithm = objects < 0 ? -1 : open_directory(objects, "sha256");
  int parent = algorithm < 0 ? -1 : open_directory(algorithm, prefix);
  if (objects < 0 || algorithm < 0 || parent < 0) { if (parent >= 0) close(parent); if (algorithm >= 0) close(algorithm); if (objects >= 0) close(objects); close(root); return 65; }

  struct stat parent_status; if (fstat(parent, &parent_status) != 0 || (uintmax_t)parent_status.st_dev != expected_parent_dev || (uintmax_t)parent_status.st_ino != expected_parent_ino) return 65;
  struct stat target;
  int target_result = fstatat(parent, hash, &target, AT_SYMLINK_NOFOLLOW);
  if (strcmp(argv[1], "verify-absent") == 0) {
    bool absent = target_result != 0 && errno == ENOENT;
    printf("{\"event\":\"verify_absent\",\"absent\":%s,\"parent_device\":%ju,\"parent_inode\":%ju}\n", absent ? "true" : "false", (uintmax_t)parent_status.st_dev, (uintmax_t)parent_status.st_ino);
    close(parent); close(algorithm); close(objects); close(root); return absent ? 0 : 3;
  }
  if (strcmp(argv[1], "sync-parent") == 0) {
    bool absent = target_result != 0 && errno == ENOENT;
    bool synced = absent && fsync(parent) == 0;
    printf("{\"event\":\"parent_synced\",\"directory_synced\":%s,\"reopened_absent\":%s,\"parent_device\":%ju,\"parent_inode\":%ju}\n", synced ? "true" : "false", absent ? "true" : "false", (uintmax_t)parent_status.st_dev, (uintmax_t)parent_status.st_ino);
    close(parent); close(algorithm); close(objects); close(root); return synced ? 0 : 68;
  }
  if (target_result != 0 || !S_ISREG(target.st_mode) || target.st_nlink != 1 || (uintmax_t)target.st_dev != expected_dev ||
      (uintmax_t)target.st_ino != expected_ino || (uintmax_t)target.st_size != expected_size) {
    close(parent); close(algorithm); close(objects); close(root); return 66;
  }
  if (unlinkat(parent, hash, 0) != 0) { close(parent); close(algorithm); close(objects); close(root); return 67; }
  struct stat after; bool absent = fstatat(parent, hash, &after, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
  printf("{\"event\":\"primary_name_unlinked\",\"removed\":true,\"directory_synced\":false,\"reopened_absent\":%s,\"target_device\":%ju,\"target_inode\":%ju,\"parent_device\":%ju,\"parent_inode\":%ju}\n",
         absent ? "true" : "false", expected_dev, expected_ino, (uintmax_t)parent_status.st_dev, (uintmax_t)parent_status.st_ino);
  close(parent); close(algorithm); close(objects); close(root); return absent ? 0 : 68;
}
