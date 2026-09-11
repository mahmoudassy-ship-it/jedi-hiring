#define _GNU_SOURCE

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <openssl/evp.h>
#include <poll.h>
#include <sys/prctl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_BYTES 26214400ULL
#define MAGIC 0xD931CA5U

struct verifier_result {
  uint32_t magic;
  uint32_t descriptor_alias_count;
  uint64_t length;
  unsigned char digest[32];
};

static void die(const char *code);

static unsigned long long process_start_ticks(pid_t pid) {
  char path[64];
  char buffer[4096];
  char *cursor;
  char *end;
  int fd;
  ssize_t count;
  int field = 3;
  (void)snprintf(path, sizeof(path), "/proc/%d/stat", pid);
  fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) die("PROCESS_STAT_UNAVAILABLE");
  count = read(fd, buffer, sizeof(buffer) - 1U);
  (void)close(fd);
  if (count <= 0) die("PROCESS_STAT_UNAVAILABLE");
  buffer[count] = '\0';
  cursor = strrchr(buffer, ')');
  if (cursor == NULL || cursor[1] != ' ') die("PROCESS_STAT_INVALID");
  cursor += 2;
  while (field < 22) {
    cursor = strchr(cursor, ' ');
    if (cursor == NULL) die("PROCESS_STAT_INVALID");
    cursor += 1;
    field += 1;
  }
  errno = 0;
  {
    unsigned long long value = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || (*end != ' ' && *end != '\0') || value == 0U) die("PROCESS_STAT_INVALID");
    return value;
  }
}

static void die(const char *code) {
  (void)fprintf(stderr, "%s:%d\n", code, errno);
  exit(2);
}

static unsigned long long parse_u64(const char *value, unsigned long long maximum) {
  char *end = NULL;
  unsigned long long result;
  errno = 0;
  result = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || result > maximum) die("ARGUMENT_INVALID");
  return result;
}

static void hex_digest(const unsigned char *digest, char output[65]) {
  static const char digits[] = "0123456789abcdef";
  size_t index;
  for (index = 0U; index < 32U; index += 1U) {
    output[index * 2U] = digits[digest[index] >> 4U];
    output[index * 2U + 1U] = digits[digest[index] & 0x0fU];
  }
  output[64] = '\0';
}

static int receive_descriptor(int socket_fd) {
  char payload;
  struct iovec iov = { .iov_base = &payload, .iov_len = sizeof(payload) };
  union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
  struct msghdr message;
  struct cmsghdr *header;
  int descriptor = -1;
  memset(&message, 0, sizeof(message));
  memset(&control, 0, sizeof(control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1U;
  message.msg_control = control.bytes;
  message.msg_controllen = sizeof(control.bytes);
  if (recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC) != 1 || payload != 'D' || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) return -1;
  header = CMSG_FIRSTHDR(&message);
  if (header == NULL || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || header->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
  memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
  if (CMSG_NXTHDR(&message, header) != NULL) { (void)close(descriptor); return -1; }
  return descriptor;
}

static uint32_t descriptor_alias_count(int descriptor) {
  DIR *directory;
  struct dirent *entry;
  struct stat expected;
  uint32_t count = 0U;
  if (fstat(descriptor, &expected) != 0) die("DESCRIPTOR_STAT_FAILED");
  directory = opendir("/proc/self/fd");
  if (directory == NULL) die("DESCRIPTOR_INVENTORY_UNAVAILABLE");
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    char *end = NULL;
    long candidate;
    struct stat status;
    errno = 0;
    candidate = strtol(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0' || candidate < 0 || candidate > INT32_MAX || candidate == dirfd(directory)) continue;
    if (fstat((int)candidate, &status) == 0 && status.st_dev == expected.st_dev && status.st_ino == expected.st_ino) count += 1U;
  }
  if (errno != 0 || closedir(directory) != 0) die("DESCRIPTOR_INVENTORY_UNAVAILABLE");
  return count;
}

static void send_descriptor(int socket_fd, int descriptor) {
  char payload = 'D';
  struct iovec iov = { .iov_base = &payload, .iov_len = sizeof(payload) };
  union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
  struct msghdr message;
  struct cmsghdr *header;
  memset(&message, 0, sizeof(message));
  memset(&control, 0, sizeof(control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1U;
  message.msg_control = control.bytes;
  message.msg_controllen = sizeof(control.bytes);
  header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  if (sendmsg(socket_fd, &message, MSG_NOSIGNAL) != 1) die("DESCRIPTOR_SEND_FAILED");
}

static void verifier(int socket_fd, unsigned long long expected_length, uid_t expected_uid, gid_t expected_gid) {
  int descriptor;
  unsigned char buffer[16384];
  unsigned long long total = 0U;
  EVP_MD_CTX *context;
  struct verifier_result result;
  uint32_t alias_count;
  char terminal;
  if (expected_uid == 0U || setgroups(0, NULL) != 0 || setgid(expected_gid) != 0 || setuid(expected_uid) != 0 ||
      getuid() != expected_uid || getgid() != expected_gid || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die("VERIFIER_IDENTITY_SETUP_FAILED");
  descriptor = receive_descriptor(socket_fd);
  if (descriptor < 0) die("DESCRIPTOR_RECEIVE_FAILED");
  alias_count = descriptor_alias_count(descriptor);
  if (alias_count != 1U) die("DESCRIPTOR_ALIAS_REJECTED");
  context = EVP_MD_CTX_new();
  if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) die("HASH_INIT_FAILED");
  for (;;) {
    ssize_t count = read(descriptor, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) die("DESCRIPTOR_READ_FAILED");
    if (count == 0) break;
    total += (unsigned long long)count;
    if (total > MAX_BYTES || EVP_DigestUpdate(context, buffer, (size_t)count) != 1) die("HASH_UPDATE_FAILED");
  }
  memset(&result, 0, sizeof(result));
  result.magic = MAGIC;
  result.descriptor_alias_count = alias_count;
  result.length = total;
  {
    unsigned int length = 0U;
    if (EVP_DigestFinal_ex(context, result.digest, &length) != 1 || length != 32U) die("HASH_FINAL_FAILED");
  }
  EVP_MD_CTX_free(context);
  if (total != expected_length || send(socket_fd, &result, sizeof(result), MSG_NOSIGNAL) != (ssize_t)sizeof(result)) die("RESULT_SEND_FAILED");
  if (recv(socket_fd, &terminal, 1U, 0) != 1 || terminal != 'X') die("TERMINAL_ACK_FAILED");
  if (close(descriptor) != 0) die("DESCRIPTOR_CLOSE_FAILED");
  exit(0);
}

int main(int argc, char **argv) {
  int pair[2];
  pid_t child;
  unsigned long long expected_length;
  unsigned long long expected_uid;
  unsigned long long expected_gid;
  struct verifier_result result;
  struct ucred credentials;
  union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))]; } credential_control;
  struct iovec result_iov;
  struct msghdr result_message;
  struct cmsghdr *credential_header;
  struct stat executable_status;
  int pidfd;
  int status;
  char digest[65];
  char approval;
  if (argc != 4) die("ARGUMENT_COUNT_INVALID");
  expected_length = parse_u64(argv[1], MAX_BYTES);
  expected_uid = parse_u64(argv[2], UINT32_MAX);
  expected_gid = parse_u64(argv[3], UINT32_MAX);
  if (fcntl(3, F_GETFL) < 0) die("SOURCE_DESCRIPTOR_INVALID");
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) die("SOCKETPAIR_FAILED");
  {
    int enabled = 1;
    if (setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) die("PEER_CREDENTIAL_SETUP_FAILED");
  }
  child = fork();
  if (child < 0) die("FORK_FAILED");
  if (child == 0) {
    (void)close(pair[0]);
    if (close(3) != 0) die("INHERITED_SOURCE_CLOSE_FAILED");
    verifier(pair[1], expected_length, (uid_t)expected_uid, (gid_t)expected_gid);
  }
  (void)close(pair[1]);
  pidfd = (int)syscall(SYS_pidfd_open, child, 0U);
  if (pidfd < 0) die("PIDFD_UNAVAILABLE");
  send_descriptor(pair[0], 3);
  if (close(3) != 0) die("SENDER_CLOSE_FAILED");
  memset(&result_message, 0, sizeof(result_message));
  memset(&credential_control, 0, sizeof(credential_control));
  result_iov.iov_base = &result;
  result_iov.iov_len = sizeof(result);
  result_message.msg_iov = &result_iov;
  result_message.msg_iovlen = 1U;
  result_message.msg_control = credential_control.bytes;
  result_message.msg_controllen = sizeof(credential_control.bytes);
  if (recvmsg(pair[0], &result_message, 0) != (ssize_t)sizeof(result) || (result_message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 || result.magic != MAGIC || result.descriptor_alias_count != 1U || result.length != expected_length) die("VERIFIER_RESULT_INVALID");
  credential_header = CMSG_FIRSTHDR(&result_message);
  if (credential_header == NULL || credential_header->cmsg_level != SOL_SOCKET || credential_header->cmsg_type != SCM_CREDENTIALS || credential_header->cmsg_len != CMSG_LEN(sizeof(struct ucred))) die("PEER_CREDENTIAL_UNAVAILABLE");
  memcpy(&credentials, CMSG_DATA(credential_header), sizeof(credentials));
  if (credentials.pid != child || (unsigned long long)credentials.uid != expected_uid || (unsigned long long)credentials.gid != expected_gid) die("PEER_CREDENTIAL_MISMATCH");
  {
    char executable_path[64];
    (void)snprintf(executable_path, sizeof(executable_path), "/proc/%d/exe", child);
    if (stat(executable_path, &executable_status) != 0) die("PEER_EXECUTABLE_UNAVAILABLE");
  }
  (void)printf("{\"event\":\"descriptor_delivered\",\"executable_device\":%llu,\"executable_inode\":%llu,\"gid\":%u,\"peer_credentials_verified\":true,\"pid\":%d,\"pidfd_supervision_active\":true,\"start_time_ticks\":%llu,\"uid\":%u}\n", (unsigned long long)executable_status.st_dev, (unsigned long long)executable_status.st_ino, credentials.gid, credentials.pid, process_start_ticks(child), credentials.uid);
  (void)fflush(stdout);
  hex_digest(result.digest, digest);
  (void)printf("{\"byte_length\":%llu,\"descriptor_alias_count\":%u,\"event\":\"verifier_result\",\"sha256\":\"%s\"}\n", (unsigned long long)result.length, result.descriptor_alias_count, digest);
  (void)fflush(stdout);
  if (read(STDIN_FILENO, &approval, 1U) != 1 || approval != 'A') die("PERSISTENCE_ACK_INVALID");
  if (send(pair[0], "X", 1U, MSG_NOSIGNAL) != 1) die("TERMINAL_SEND_FAILED");
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) die("VERIFIER_TERMINATION_FAILED");
  {
    struct pollfd poll_descriptor = { .fd = pidfd, .events = POLLIN };
    if (poll(&poll_descriptor, 1U, 1000) != 1) die("PIDFD_TERMINATION_UNCONFIRMED");
  }
  (void)close(pidfd);
  (void)close(pair[0]);
  (void)printf("{\"event\":\"receiver_terminated\",\"receiver_descriptor_closed\":true,\"status\":\"clean_exit_reaped\"}\n");
  (void)fflush(stdout);
  return 0;
}
