#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0x40000000
#endif

#define D9_MAX_PACKET_BYTES 65536U
#define D9_MAX_ANCILLARY_FDS 8U
#define D9_OPERATION_NONCE_HEX 64U
#define D9_DESCRIPTOR_TOKEN_HEX 64U
#define D9_REQUEST_DIGEST_HEX 64U
#define D9_GRANT_CODE_MAX 96U
#define D9_PEER_TIMEOUT_MS 5000
#define D9_PEER_TERM_GRACE_MS 250
#define D9_CONFINEMENT_CODE "seccomp_single_process_no_fd_transfer_v1"

#if defined(__x86_64__)
#define D9_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define D9_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "D9 synthetic confinement supports only x86_64 and aarch64"
#endif

#ifndef D9_SYNTHETIC_BUILD_VARIANT
#define D9_SYNTHETIC_BUILD_VARIANT 0
#endif

static const char *synthetic_descriptor_bytes = "synthetic-d9-handle\n";
volatile const int d9_synthetic_build_variant = D9_SYNTHETIC_BUILD_VARIANT;
static char cleanup_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};

struct received_packet {
  ssize_t length;
  int flags;
  int fds[D9_MAX_ANCILLARY_FDS + 1U];
  size_t fd_count;
  bool has_credentials;
  struct ucred credentials;
};

struct descriptor_grant {
  char slot_code[D9_GRANT_CODE_MAX + 1U];
  char runtime_role_code[D9_GRANT_CODE_MAX + 1U];
  char access_code[D9_GRANT_CODE_MAX + 1U];
};

static void close_received_fds(struct received_packet *packet) {
  size_t index;
  for (index = 0; index < packet->fd_count; index += 1U) {
    if (packet->fds[index] >= 0) close(packet->fds[index]);
    packet->fds[index] = -1;
  }
  packet->fd_count = 0U;
}

static void cleanup_socket(void) {
  if (cleanup_socket_path[0] != '\0') unlink(cleanup_socket_path);
}

static void print_error_result(const char *code) {
  printf("{\"event\":\"result\",\"status\":\"rejected\",\"error_code\":\"%s\"}\n", code);
  fflush(stdout);
}

static bool parse_unsigned(const char *value, unsigned long long maximum, unsigned long long *result) {
  char *end = NULL;
  unsigned long long parsed;
  if (value == NULL || value[0] == '\0' || value[0] == '-') return false;
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed > maximum) return false;
  *result = parsed;
  return true;
}

static bool is_lower_hex(const char *value, size_t exact_length) {
  size_t index;
  if (value == NULL || strlen(value) != exact_length) return false;
  for (index = 0; index < exact_length; index += 1U) {
    const char byte = value[index];
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) return false;
  }
  return true;
}

static bool is_stable_code(const char *value) {
  const size_t length = value == NULL ? 0U : strlen(value);
  size_t index;
  if (length < 3U || length > D9_GRANT_CODE_MAX ||
      !((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= '0' && value[0] <= '9')) ||
      !((value[length - 1U] >= 'a' && value[length - 1U] <= 'z') ||
        (value[length - 1U] >= '0' && value[length - 1U] <= '9'))) return false;
  for (index = 1U; index + 1U < length; index += 1U) {
    const char byte = value[index];
    if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
          byte == '.' || byte == '_' || byte == '-')) return false;
  }
  return true;
}

static int read_operation_material(int fd, char nonce[D9_OPERATION_NONCE_HEX + 1U],
                                   char token[D9_DESCRIPTOR_TOKEN_HEX + 1U],
                                   char request_digest[D9_REQUEST_DIGEST_HEX + 1U],
                                   struct descriptor_grant grants[D9_MAX_ANCILLARY_FDS],
                                   size_t *grant_count) {
  char material[4096];
  char *lines[4U + (3U * D9_MAX_ANCILLARY_FDS)];
  char *cursor;
  size_t used = 0U;
  size_t index;
  unsigned long long parsed_grant_count;
  while (used < sizeof(material) - 1U) {
    const ssize_t amount = read(fd, material + used, sizeof(material) - 1U - used);
    if (amount < 0 && errno == EINTR) continue;
    if (amount < 0) return -1;
    if (amount == 0) break;
    used += (size_t)amount;
  }
  material[used] = '\0';
  cursor = material;
  for (index = 0U; index < 4U; index += 1U) {
    char *newline;
    lines[index] = cursor;
    newline = strchr(cursor, '\n');
    if (newline == NULL) {
      errno = EPROTO;
      return -1;
    }
    *newline = '\0';
    cursor = newline + 1;
  }
  if (strlen(lines[0]) != D9_OPERATION_NONCE_HEX ||
      strlen(lines[1]) != D9_DESCRIPTOR_TOKEN_HEX || strlen(lines[2]) != D9_REQUEST_DIGEST_HEX ||
      !parse_unsigned(lines[3], D9_MAX_ANCILLARY_FDS, &parsed_grant_count) || parsed_grant_count == 0U) {
    errno = EPROTO;
    return -1;
  }
  *grant_count = (size_t)parsed_grant_count;
  for (index = 0U; index < 3U * *grant_count; index += 1U) {
    char *newline;
    lines[4U + index] = cursor;
    newline = strchr(cursor, '\n');
    if (newline == NULL) {
      errno = EPROTO;
      return -1;
    }
    *newline = '\0';
    cursor = newline + 1;
  }
  if (*cursor != '\0') {
    errno = EPROTO;
    return -1;
  }
  memcpy(nonce, lines[0], D9_OPERATION_NONCE_HEX);
  nonce[D9_OPERATION_NONCE_HEX] = '\0';
  memcpy(token, lines[1], D9_DESCRIPTOR_TOKEN_HEX);
  token[D9_DESCRIPTOR_TOKEN_HEX] = '\0';
  memcpy(request_digest, lines[2], D9_REQUEST_DIGEST_HEX);
  request_digest[D9_REQUEST_DIGEST_HEX] = '\0';
  for (index = 0U; index < *grant_count; index += 1U) {
    const char *slot_code = lines[4U + (3U * index)];
    const char *runtime_role_code = lines[5U + (3U * index)];
    const char *access_code = lines[6U + (3U * index)];
    if (!is_stable_code(slot_code) || !is_stable_code(runtime_role_code) || !is_stable_code(access_code)) {
      errno = EPROTO;
      return -1;
    }
    memcpy(grants[index].slot_code, slot_code, strlen(slot_code) + 1U);
    memcpy(grants[index].runtime_role_code, runtime_role_code, strlen(runtime_role_code) + 1U);
    memcpy(grants[index].access_code, access_code, strlen(access_code) + 1U);
  }
  if (!is_lower_hex(nonce, D9_OPERATION_NONCE_HEX) || !is_lower_hex(token, D9_DESCRIPTOR_TOKEN_HEX) ||
      !is_lower_hex(request_digest, D9_REQUEST_DIGEST_HEX)) {
    errno = EPROTO;
    return -1;
  }
  memset(material, 0, sizeof(material));
  return 0;
}

static int safe_open_root(const char *root_path) {
  struct open_how how;
  int fd;
  struct stat status;
  memset(&how, 0, sizeof(how));
  how.flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
  how.resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
  fd = (int)syscall(SYS_openat2, AT_FDCWD, root_path, &how, sizeof(how));
  if (fd < 0) return -1;
  if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode) ||
      (status.st_uid != 0 && status.st_uid != geteuid()) || (status.st_mode & 0022) != 0) {
    close(fd);
    errno = EPERM;
    return -1;
  }
  return fd;
}

static int safe_open_beneath(int root_fd, const char *relative_path, int flags, mode_t mode) {
  struct open_how how;
  memset(&how, 0, sizeof(how));
  how.flags = (uint64_t)(flags | O_CLOEXEC | O_NOFOLLOW);
  how.mode = (uint64_t)mode;
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
  return (int)syscall(SYS_openat2, root_fd, relative_path, &how, sizeof(how));
}

static int wait_readable(int fd, int timeout_ms) {
  struct pollfd descriptor;
  int result;
  descriptor.fd = fd;
  descriptor.events = POLLIN;
  descriptor.revents = 0;
  do {
    result = poll(&descriptor, 1, timeout_ms);
  } while (result < 0 && errno == EINTR);
  if (result <= 0) return result;
  if ((descriptor.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
    errno = EIO;
    return -1;
  }
  return 1;
}

static int receive_packet(int socket_fd, char *payload, size_t payload_capacity, struct received_packet *packet) {
  char ancillary[CMSG_SPACE(sizeof(int) * (D9_MAX_ANCILLARY_FDS + 1U)) + CMSG_SPACE(sizeof(struct ucred))];
  struct iovec vector;
  struct msghdr message;
  struct cmsghdr *header;

  memset(packet, 0, sizeof(*packet));
  memset(&message, 0, sizeof(message));
  memset(ancillary, 0, sizeof(ancillary));
  vector.iov_base = payload;
  vector.iov_len = payload_capacity;
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = ancillary;
  message.msg_controllen = sizeof(ancillary);

  packet->length = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
  if (packet->length < 0) return -1;
  packet->flags = message.msg_flags;

  for (header = CMSG_FIRSTHDR(&message); header != NULL; header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET) {
      errno = EPROTO;
      close_received_fds(packet);
      return -1;
    }
    if (header->cmsg_type == SCM_RIGHTS) {
      const size_t bytes = header->cmsg_len >= CMSG_LEN(0) ? header->cmsg_len - CMSG_LEN(0) : 0U;
      const size_t count = bytes / sizeof(int);
      size_t index;
      const int *received = (const int *)CMSG_DATA(header);
      if (bytes % sizeof(int) != 0U || packet->fd_count + count > D9_MAX_ANCILLARY_FDS + 1U) {
        errno = EMSGSIZE;
        close_received_fds(packet);
        return -1;
      }
      for (index = 0; index < count; index += 1U) packet->fds[packet->fd_count++] = received[index];
    } else if (header->cmsg_type == SCM_CREDENTIALS) {
      if (packet->has_credentials || header->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
        errno = EPROTO;
        close_received_fds(packet);
        return -1;
      }
      memcpy(&packet->credentials, CMSG_DATA(header), sizeof(struct ucred));
      packet->has_credentials = true;
    } else {
      errno = EPROTO;
      close_received_fds(packet);
      return -1;
    }
  }

  return 0;
}

static int send_packet(int socket_fd, const char *payload, size_t length, const int *fds, size_t fd_count) {
  char ancillary[CMSG_SPACE(sizeof(int) * D9_MAX_ANCILLARY_FDS)];
  struct iovec vector;
  struct msghdr message;
  ssize_t sent;

  if (length > D9_MAX_PACKET_BYTES || fd_count > D9_MAX_ANCILLARY_FDS) {
    errno = EMSGSIZE;
    return -1;
  }
  memset(&message, 0, sizeof(message));
  vector.iov_base = (void *)payload;
  vector.iov_len = length;
  message.msg_iov = &vector;
  message.msg_iovlen = 1;

  if (fd_count > 0U) {
    struct cmsghdr *header;
    memset(ancillary, 0, sizeof(ancillary));
    message.msg_control = ancillary;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
    memcpy(CMSG_DATA(header), fds, sizeof(int) * fd_count);
  }

  do {
    sent = sendmsg(socket_fd, &message, MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);
  if (sent < 0) return -1;
  if ((size_t)sent != length) {
    errno = EIO;
    return -1;
  }
  return 0;
}

static int terminate_and_confirm(int peer_pidfd, bool *escalated) {
  int result;
  *escalated = false;
  do {
    result = (int)syscall(SYS_pidfd_send_signal, peer_pidfd, SIGTERM, NULL, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0 && errno != ESRCH) return -1;
  result = wait_readable(peer_pidfd, D9_PEER_TERM_GRACE_MS);
  if (result == 1) return 0;
  if (result < 0) return -1;
  *escalated = true;
  do {
    result = (int)syscall(SYS_pidfd_send_signal, peer_pidfd, SIGKILL, NULL, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0 && errno != ESRCH) return -1;
  result = wait_readable(peer_pidfd, D9_PEER_TIMEOUT_MS);
  return result == 1 ? 0 : -1;
}

static int open_peer_executable(pid_t peer_pid, const struct stat *expected_status) {
  char proc_path[64];
  struct stat peer_status;
  int peer_executable_fd;
  const int length = snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", peer_pid);
  if (length < 1 || (size_t)length >= sizeof(proc_path)) {
    errno = EOVERFLOW;
    return -1;
  }
  peer_executable_fd = open(proc_path, O_RDONLY | O_CLOEXEC);
  if (peer_executable_fd < 0) return -1;
  if (fstat(peer_executable_fd, &peer_status) != 0 || !S_ISREG(peer_status.st_mode) ||
      peer_status.st_dev != expected_status->st_dev || peer_status.st_ino != expected_status->st_ino ||
      peer_status.st_size != expected_status->st_size) {
    close(peer_executable_fd);
    errno = EPERM;
    return -1;
  }
  return peer_executable_fd;
}

static bool peer_confinement_is_active(pid_t peer_pid) {
  char proc_path[64];
  char status[8192];
  ssize_t used = 0;
  int status_fd = -1;
  DIR *task_directory = NULL;
  struct dirent *entry;
  unsigned task_count = 0U;
  const int status_length = snprintf(proc_path, sizeof(proc_path), "/proc/%d/status", peer_pid);
  if (status_length < 1 || (size_t)status_length >= sizeof(proc_path)) return false;
  status_fd = open(proc_path, O_RDONLY | O_CLOEXEC);
  if (status_fd < 0) return false;
  while (used < (ssize_t)(sizeof(status) - 1U)) {
    const ssize_t amount = read(status_fd, status + used, sizeof(status) - 1U - (size_t)used);
    if (amount < 0 && errno == EINTR) continue;
    if (amount < 0) {
      close(status_fd);
      return false;
    }
    if (amount == 0) break;
    used += amount;
  }
  close(status_fd);
  status[used] = '\0';
  if (strstr(status, "NoNewPrivs:\t1\n") == NULL || strstr(status, "Seccomp:\t2\n") == NULL) return false;

  const int task_length = snprintf(proc_path, sizeof(proc_path), "/proc/%d/task", peer_pid);
  if (task_length < 1 || (size_t)task_length >= sizeof(proc_path)) return false;
  task_directory = opendir(proc_path);
  if (task_directory == NULL) return false;
  while ((entry = readdir(task_directory)) != NULL) {
    if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') task_count += 1U;
  }
  closedir(task_directory);
  return task_count == 1U;
}

static int install_peer_confinement(void) {
  struct rlimit nofile_limit = {64U, 64U};
  struct rlimit process_limit = {1U, 1U};
  struct rlimit address_limit = {536870912U, 536870912U};
  struct rlimit cpu_limit = {600U, 600U};
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, D9_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, nr)),
#ifdef __NR_clone
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_clone3
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_fork
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_vfork
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_sendmsg
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_sendmmsg
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_execve
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_execveat
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_pidfd_getfd
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pidfd_getfd, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_ptrace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_process_vm_readv
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_process_vm_writev
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_io_uring_setup
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_unshare
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#ifdef __NR_setns
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setns, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  const struct sock_fprog program = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  if (setrlimit(RLIMIT_NOFILE, &nofile_limit) != 0 || setrlimit(RLIMIT_NPROC, &process_limit) != 0 ||
      setrlimit(RLIMIT_AS, &address_limit) != 0 || setrlimit(RLIMIT_CPU, &cpu_limit) != 0 ||
      prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return -1;
  return 0;
}

static int probe_command(void) {
  int sockets[2] = {-1, -1};
  int peer_pidfd = -1;
  int root_fd = -1;
  int opened_fd = -1;
  int lock_probe_fd = -1;
  int transferred_fd = -1;
  int received_fd = -1;
  bool seqpacket = false;
  bool peer_credentials = false;
  bool peer_pidfd_supported = false;
  bool scm_rights = false;
  bool cmsg_cloexec = false;
  bool openat2_supported = false;
  bool flock_supported = false;
  struct ucred credentials;
  socklen_t credentials_size = sizeof(credentials);
  socklen_t pidfd_size = sizeof(peer_pidfd);

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0) {
    seqpacket = true;
    if (getsockopt(sockets[0], SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_size) == 0 &&
        credentials_size == sizeof(credentials) && credentials.pid == getpid() &&
        credentials.uid == getuid() && credentials.gid == getgid()) peer_credentials = true;
    if (getsockopt(sockets[0], SOL_SOCKET, SO_PEERPIDFD, &peer_pidfd, &pidfd_size) == 0 &&
        pidfd_size == sizeof(peer_pidfd) && syscall(SYS_pidfd_send_signal, peer_pidfd, 0, NULL, 0) == 0) {
      peer_pidfd_supported = true;
    }

    transferred_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (transferred_fd >= 0 && send_packet(sockets[0], "x", 1U, &transferred_fd, 1U) == 0) {
      char payload[2] = {0};
      struct received_packet packet;
      if (receive_packet(sockets[1], payload, 1U, &packet) == 0 && packet.length == 1 && packet.fd_count == 1U) {
        received_fd = packet.fds[0];
        packet.fds[0] = -1;
        packet.fd_count = 0U;
        scm_rights = true;
        cmsg_cloexec = (fcntl(received_fd, F_GETFD) & FD_CLOEXEC) != 0;
      }
      close_received_fds(&packet);
    }
  }

  root_fd = safe_open_root(".");
  if (root_fd >= 0) {
    opened_fd = safe_open_beneath(root_fd, ".", O_PATH | O_DIRECTORY, 0);
    if (opened_fd >= 0) openat2_supported = true;
  }
  lock_probe_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (lock_probe_fd >= 0 && flock(lock_probe_fd, LOCK_EX | LOCK_NB) == 0) {
    flock_supported = true;
    (void)flock(lock_probe_fd, LOCK_UN);
  }

  printf("{\"event\":\"probe\",\"linux\":true,\"seqpacket\":%s,\"peer_credentials\":%s,\"peer_pidfd\":%s,\"scm_rights\":%s,\"msg_cmsg_cloexec\":%s,\"openat2\":%s,\"flock\":%s,\"pid\":%ld,\"uid\":%lu,\"gid\":%lu}\n",
         seqpacket ? "true" : "false", peer_credentials ? "true" : "false",
         peer_pidfd_supported ? "true" : "false", scm_rights ? "true" : "false",
         cmsg_cloexec ? "true" : "false", openat2_supported ? "true" : "false",
         flock_supported ? "true" : "false", (long)getpid(), (unsigned long)getuid(),
         (unsigned long)getgid());

  if (received_fd >= 0) close(received_fd);
  if (transferred_fd >= 0) close(transferred_fd);
  if (opened_fd >= 0) close(opened_fd);
  if (lock_probe_fd >= 0) close(lock_probe_fd);
  if (root_fd >= 0) close(root_fd);
  if (peer_pidfd >= 0) close(peer_pidfd);
  if (sockets[0] >= 0) close(sockets[0]);
  if (sockets[1] >= 0) close(sockets[1]);
  return (seqpacket && peer_credentials && peer_pidfd_supported && scm_rights && cmsg_cloexec && openat2_supported && flock_supported) ? 0 : 2;
}

static int create_listener(const char *socket_path, uid_t expected_uid, gid_t expected_gid) {
  int socket_fd;
  int pass_credentials = 1;
  struct sockaddr_un address;
  struct stat status;

  if (strlen(socket_path) >= sizeof(address.sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (lstat(socket_path, &status) == 0 || errno != ENOENT) {
    errno = EEXIST;
    return -1;
  }
  socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) return -1;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_PASSCRED, &pass_credentials, sizeof(pass_credentials)) != 0) {
    const int saved = errno;
    close(socket_fd);
    errno = saved;
    return -1;
  }
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, socket_path, strlen(socket_path) + 1U);
  if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      chown(socket_path, expected_uid, expected_gid) != 0 ||
      chmod(socket_path, 0600) != 0 || listen(socket_fd, 1) != 0) {
    const int saved = errno;
    close(socket_fd);
    unlink(socket_path);
    errno = saved;
    return -1;
  }
  memcpy(cleanup_socket_path, socket_path, strlen(socket_path) + 1U);
  return socket_fd;
}

static bool packet_credentials_match(const struct received_packet *packet, const struct ucred *peer) {
  return packet->has_credentials && packet->credentials.pid == peer->pid &&
         packet->credentials.uid == peer->uid && packet->credentials.gid == peer->gid;
}

static int broker_command(int argc, char **argv) {
  const char *socket_path;
  const char *root_path;
  const char *relative_path;
  char nonce[D9_OPERATION_NONCE_HEX + 1U] = {0};
  char token[D9_DESCRIPTOR_TOKEN_HEX + 1U] = {0};
  char expected_request_digest[D9_REQUEST_DIGEST_HEX + 1U] = {0};
  struct descriptor_grant grants[D9_MAX_ANCILLARY_FDS];
  size_t grant_count = 0U;
  const char *scenario;
  unsigned long long expected_uid_raw;
  unsigned long long expected_gid_raw;
  uid_t expected_uid;
  gid_t expected_gid;
  int listener_fd = -1;
  int peer_fd = -1;
  int peer_pidfd = -1;
  int expected_executable_fd = -1;
  int peer_executable_fd = -1;
  int root_fd = -1;
  int source_fds[D9_MAX_ANCILLARY_FDS];
  int pass_credentials = 1;
  struct ucred peer;
  struct stat expected_executable_status;
  socklen_t peer_size = sizeof(peer);
  socklen_t peer_pidfd_size = sizeof(peer_pidfd);
  struct received_packet request;
  char payload[D9_MAX_PACKET_BYTES + 1U];
  char claimed_nonce[D9_OPERATION_NONCE_HEX + 1U] = {0};
  char claimed_request_digest[D9_REQUEST_DIGEST_HEX + 1U] = {0};
  unsigned claimed_uid;
  unsigned claimed_gid;
  int claimed_pid;
  int consumed = 0;
  char canonical_request[512];
  char response[1024];
  char expected_ack[1024];
  int result = 2;
  bool ack_same_channel = false;
  bool replay_rejected = false;
  bool termination_confirmed = false;
  bool termination_escalated = false;
  size_t index;

  for (index = 0U; index < D9_MAX_ANCILLARY_FDS; index += 1U) source_fds[index] = -1;

  if (argc != 8) {
    print_error_result("ARGUMENTS_INVALID");
    return 2;
  }
  socket_path = argv[2];
  root_path = argv[3];
  relative_path = argv[4];
  scenario = argv[7];
  if (!parse_unsigned(argv[5], UINT32_MAX, &expected_uid_raw) ||
      !parse_unsigned(argv[6], UINT32_MAX, &expected_gid_raw) ||
      read_operation_material(3, nonce, token, expected_request_digest,
                              grants, &grant_count) != 0 ||
      (strcmp(scenario, "normal") != 0 && strcmp(scenario, "replay") != 0 &&
       strcmp(scenario, "oversize") != 0 && strcmp(scenario, "too_many_fds") != 0 &&
       strcmp(scenario, "spoof_uid") != 0 && strcmp(scenario, "spoof_gid") != 0 &&
       strcmp(scenario, "spoof_pid") != 0 &&
       strcmp(scenario, "build_substitution") != 0 &&
       strcmp(scenario, "malformed_packet") != 0 &&
       strcmp(scenario, "noncanonical_packet") != 0 &&
       strcmp(scenario, "wrong_nonce") != 0 &&
       strcmp(scenario, "wrong_request_digest") != 0 &&
       strcmp(scenario, "wrong_descriptor_metadata") != 0 &&
       strcmp(scenario, "ignore_sigterm") != 0 &&
       strcmp(scenario, "fork_escape") != 0 &&
       strcmp(scenario, "fd_transfer_escape") != 0)) {
    print_error_result("ARGUMENTS_INVALID");
    return 2;
  }
  expected_uid = (uid_t)expected_uid_raw;
  expected_gid = (gid_t)expected_gid_raw;

  expected_executable_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (expected_executable_fd < 0 || fstat(expected_executable_fd, &expected_executable_status) != 0 ||
      !S_ISREG(expected_executable_status.st_mode)) {
    print_error_result("EXPECTED_EXECUTABLE_UNAVAILABLE");
    goto cleanup;
  }

  if (atexit(cleanup_socket) != 0) {
    print_error_result("SOCKET_CLEANUP_UNAVAILABLE");
    return 2;
  }
  listener_fd = create_listener(socket_path, expected_uid, expected_gid);
  if (listener_fd < 0) {
    print_error_result("SOCKET_LISTEN_FAILED");
    goto cleanup;
  }
  printf("{\"event\":\"ready\",\"pid\":%ld}\n", (long)getpid());
  fflush(stdout);

  peer_fd = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
  if (peer_fd < 0 || setsockopt(peer_fd, SOL_SOCKET, SO_PASSCRED, &pass_credentials, sizeof(pass_credentials)) != 0 ||
      getsockopt(peer_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 || peer_size != sizeof(peer) ||
      getsockopt(peer_fd, SOL_SOCKET, SO_PEERPIDFD, &peer_pidfd, &peer_pidfd_size) != 0 || peer_pidfd_size != sizeof(peer_pidfd)) {
    print_error_result("PEER_CREDENTIAL_UNAVAILABLE");
    goto cleanup;
  }
  if (peer.uid != expected_uid || peer.gid != expected_gid) {
    print_error_result("PEER_MISMATCH");
    goto terminate_peer;
  }
  peer_executable_fd = open_peer_executable(peer.pid, &expected_executable_status);
  if (peer_executable_fd < 0) {
    print_error_result("PEER_EXECUTABLE_MISMATCH");
    goto terminate_peer;
  }
  if (wait_readable(peer_fd, D9_PEER_TIMEOUT_MS) != 1) {
    print_error_result("PEER_TIMEOUT");
    goto terminate_peer;
  }
  if (receive_packet(peer_fd, payload, D9_MAX_PACKET_BYTES, &request) != 0) {
    print_error_result(errno == EMSGSIZE ? "DESCRIPTOR_LIMIT" : "PACKET_INVALID");
    goto terminate_peer;
  }
  if ((request.flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || request.length > (ssize_t)D9_MAX_PACKET_BYTES) {
    close_received_fds(&request);
    print_error_result((request.flags & MSG_CTRUNC) != 0 ? "DESCRIPTOR_LIMIT" : "PACKET_TOO_LARGE");
    goto terminate_peer;
  }
  if (request.fd_count > D9_MAX_ANCILLARY_FDS) {
    close_received_fds(&request);
    print_error_result("DESCRIPTOR_LIMIT");
    goto terminate_peer;
  }
  if (!packet_credentials_match(&request, &peer)) {
    close_received_fds(&request);
    print_error_result("PEER_CREDENTIAL_CHANGED");
    goto terminate_peer;
  }
  if (request.fd_count != 0U) {
    close_received_fds(&request);
    print_error_result("UNEXPECTED_DESCRIPTOR");
    goto terminate_peer;
  }
  if ((size_t)request.length >= sizeof(payload)) {
    print_error_result("PACKET_TOO_LARGE");
    goto terminate_peer;
  }
  payload[request.length] = '\0';
  if (sscanf(payload,
             "{\"claimed_gid\":%u,\"claimed_pid\":%d,\"claimed_uid\":%u,\"confinement_code\":\"" D9_CONFINEMENT_CODE "\",\"operation_nonce\":\"%64[0-9a-f]\",\"request_digest_sha256\":\"%64[0-9a-f]\",\"type\":\"hello\"}%n",
             &claimed_gid, &claimed_pid, &claimed_uid, claimed_nonce,
             claimed_request_digest, &consumed) != 5 ||
      consumed != request.length || !is_lower_hex(claimed_nonce, D9_OPERATION_NONCE_HEX) ||
      !is_lower_hex(claimed_request_digest, D9_REQUEST_DIGEST_HEX)) {
    print_error_result("PACKET_INVALID");
    goto terminate_peer;
  }
  snprintf(canonical_request, sizeof(canonical_request),
           "{\"claimed_gid\":%u,\"claimed_pid\":%d,\"claimed_uid\":%u,\"confinement_code\":\"" D9_CONFINEMENT_CODE "\",\"operation_nonce\":\"%s\",\"request_digest_sha256\":\"%s\",\"type\":\"hello\"}",
           claimed_gid, claimed_pid, claimed_uid, claimed_nonce, claimed_request_digest);
  if (strcmp(payload, canonical_request) != 0) {
    print_error_result("PACKET_NOT_CANONICAL");
    goto terminate_peer;
  }
  if (claimed_pid != peer.pid || claimed_uid != peer.uid || claimed_gid != peer.gid) {
    print_error_result("PEER_CLAIM_MISMATCH");
    goto terminate_peer;
  }
  if (strcmp(claimed_nonce, nonce) != 0) {
    print_error_result("NONCE_MISMATCH");
    goto terminate_peer;
  }
  if (strcmp(claimed_request_digest, expected_request_digest) != 0) {
    print_error_result("REQUEST_DIGEST_MISMATCH");
    goto terminate_peer;
  }
  if (!peer_confinement_is_active(peer.pid)) {
    print_error_result("PEER_CONFINEMENT_MISSING");
    goto terminate_peer;
  }

  close(peer_executable_fd);
  peer_executable_fd = open_peer_executable(peer.pid, &expected_executable_status);
  if (peer_executable_fd < 0) {
    print_error_result("PEER_EXECUTABLE_MISMATCH");
    goto terminate_peer;
  }

  root_fd = safe_open_root(root_path);
  if (root_fd < 0) {
    print_error_result("SAFE_OPEN_FAILED");
    goto terminate_peer;
  }
  for (index = 0U; index < grant_count; index += 1U) {
    struct stat source_status;
    source_fds[index] = safe_open_beneath(root_fd, relative_path, O_RDONLY, 0);
    if (source_fds[index] < 0) {
      print_error_result("SAFE_OPEN_FAILED");
      goto terminate_peer;
    }
    if (fstat(source_fds[index], &source_status) != 0 || !S_ISREG(source_status.st_mode)) {
      print_error_result("DESCRIPTOR_TYPE_INVALID");
      goto terminate_peer;
    }
  }
  {
    size_t used = (size_t)snprintf(response, sizeof(response),
                                  "{\"descriptor_count\":%zu,\"descriptor_token\":\"%s\",\"descriptors\":[",
                                  grant_count, token);
    if (used >= sizeof(response)) {
      print_error_result("PACKET_TOO_LARGE");
      goto terminate_peer;
    }
    for (index = 0U; index < grant_count; index += 1U) {
      const int amount = snprintf(response + used, sizeof(response) - used,
                                  "%s{\"access_code\":\"%s\",\"ordinal\":%zu,\"runtime_role_code\":\"%s\",\"slot_code\":\"%s\"}",
                                  index == 0U ? "" : ",", grants[index].access_code, index,
                                  grants[index].runtime_role_code, grants[index].slot_code);
      if (amount < 0 || (size_t)amount >= sizeof(response) - used) {
        print_error_result("PACKET_TOO_LARGE");
        goto terminate_peer;
      }
      used += (size_t)amount;
    }
    if ((size_t)snprintf(response + used, sizeof(response) - used,
                         "],\"operation_nonce\":\"%s\",\"request_digest_sha256\":\"%s\",\"type\":\"descriptor\"}",
                         nonce, expected_request_digest) >= sizeof(response) - used) {
      print_error_result("PACKET_TOO_LARGE");
      goto terminate_peer;
    }
  }
  if (send_packet(peer_fd, response, strlen(response), source_fds, grant_count) != 0) {
    print_error_result("DESCRIPTOR_SEND_FAILED");
    goto terminate_peer;
  }

  snprintf(expected_ack, sizeof(expected_ack),
           "{\"descriptor_count\":%zu,\"descriptor_token\":\"%s\",\"operation_nonce\":\"%s\",\"request_digest_sha256\":\"%s\",\"status\":\"closed\",\"type\":\"descriptor_ack\"}",
           grant_count, token, nonce, expected_request_digest);
  if (wait_readable(peer_fd, D9_PEER_TIMEOUT_MS) != 1 ||
      receive_packet(peer_fd, payload, D9_MAX_PACKET_BYTES, &request) != 0 ||
      (request.flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || request.fd_count != 0U ||
      !packet_credentials_match(&request, &peer)) {
    close_received_fds(&request);
    print_error_result("ACK_INVALID");
    goto terminate_peer;
  }
  payload[request.length] = '\0';
  ack_same_channel = strcmp(payload, expected_ack) == 0;
  if (!ack_same_channel) {
    print_error_result("ACK_INVALID");
    goto terminate_peer;
  }

  if (strcmp(scenario, "replay") == 0) {
    if (wait_readable(peer_fd, D9_PEER_TIMEOUT_MS) != 1 ||
        receive_packet(peer_fd, payload, D9_MAX_PACKET_BYTES, &request) != 0 ||
        (request.flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || request.fd_count != 0U ||
        !packet_credentials_match(&request, &peer)) {
      close_received_fds(&request);
      print_error_result("REPLAY_TEST_INVALID");
      goto terminate_peer;
    }
    payload[request.length] = '\0';
    replay_rejected = strcmp(payload, expected_ack) == 0;
    if (!replay_rejected) {
      print_error_result("REPLAY_TEST_INVALID");
      goto terminate_peer;
    }
  }

terminate_peer:
  if (peer_pidfd >= 0 && terminate_and_confirm(peer_pidfd, &termination_escalated) == 0) termination_confirmed = true;
  if (ack_same_channel && termination_confirmed && (strcmp(scenario, "replay") != 0 || replay_rejected)) {
    printf("{\"ack_same_channel\":true,\"descriptor_cloexec\":true,\"descriptor_count\":%zu,\"descriptor_metadata_verified\":true,\"event\":\"result\",\"peer_gid\":%u,\"peer_pid\":%d,\"peer_uid\":%u,\"replay_rejected\":%s,\"status\":\"ok\",\"termination_confirmed\":true,\"termination_escalated\":%s}\n",
           grant_count, peer.gid, peer.pid, peer.uid, replay_rejected ? "true" : "false",
           termination_escalated ? "true" : "false");
    fflush(stdout);
    result = 0;
  }

cleanup:
  for (index = 0U; index < D9_MAX_ANCILLARY_FDS; index += 1U) {
    if (source_fds[index] >= 0) close(source_fds[index]);
  }
  if (root_fd >= 0) close(root_fd);
  if (peer_pidfd >= 0) close(peer_pidfd);
  if (peer_executable_fd >= 0) close(peer_executable_fd);
  if (expected_executable_fd >= 0) close(expected_executable_fd);
  if (peer_fd >= 0) close(peer_fd);
  if (listener_fd >= 0) close(listener_fd);
  return result;
}

static int connect_peer(const char *socket_path) {
  int socket_fd;
  struct sockaddr_un address;
  if (strlen(socket_path) >= sizeof(address.sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) return -1;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, socket_path, strlen(socket_path) + 1U);
  if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    const int saved = errno;
    close(socket_fd);
    errno = saved;
    return -1;
  }
  return socket_fd;
}

static int peer_command(int argc, char **argv) {
  const char *socket_path;
  char nonce[D9_OPERATION_NONCE_HEX + 1U] = {0};
  char token[D9_DESCRIPTOR_TOKEN_HEX + 1U] = {0};
  char request_digest[D9_REQUEST_DIGEST_HEX + 1U] = {0};
  struct descriptor_grant grants[D9_MAX_ANCILLARY_FDS];
  size_t grant_count = 0U;
  const char *scenario;
  int socket_fd = -1;
  char request[512];
  char expected_response[1024];
  char ack[1024];
  uid_t claimed_uid = getuid();
  gid_t claimed_gid = getgid();
  pid_t claimed_pid = getpid();
  size_t index;

  if (argc != 4) return 2;
  socket_path = argv[2];
  scenario = argv[3];
  if (read_operation_material(3, nonce, token, request_digest,
                              grants, &grant_count) != 0) return 2;
  if (strcmp(scenario, "wrong_descriptor_metadata") == 0) {
    memcpy(grants[0].access_code, "substituted", sizeof("substituted"));
  }
  if (strcmp(scenario, "ignore_sigterm") == 0 && signal(SIGTERM, SIG_IGN) == SIG_ERR) return 2;
  socket_fd = connect_peer(socket_path);
  if (socket_fd < 0) return 2;

  if (strcmp(scenario, "oversize") == 0) {
    char *oversize = malloc(D9_MAX_PACKET_BYTES + 1U);
    int send_result;
    if (oversize == NULL) {
      close(socket_fd);
      return 2;
    }
    memset(oversize, 'x', D9_MAX_PACKET_BYTES + 1U);
    send_result = send(socket_fd, oversize, D9_MAX_PACKET_BYTES + 1U, MSG_NOSIGNAL) < 0 ? 2 : 0;
    free(oversize);
    if (send_result != 0) {
      close(socket_fd);
      return send_result;
    }
    for (;;) pause();
  }

  if (strcmp(scenario, "spoof_uid") == 0) claimed_uid = claimed_uid == UINT32_MAX ? claimed_uid - 1U : claimed_uid + 1U;
  if (strcmp(scenario, "spoof_gid") == 0) claimed_gid = claimed_gid == UINT32_MAX ? claimed_gid - 1U : claimed_gid + 1U;
  if (strcmp(scenario, "spoof_pid") == 0) claimed_pid = claimed_pid == INT32_MAX ? claimed_pid - 1 : claimed_pid + 1;
  if (strcmp(scenario, "malformed_packet") == 0) {
    snprintf(request, sizeof(request), "{\"type\":\"hello\"");
  } else if (strcmp(scenario, "noncanonical_packet") == 0) {
    snprintf(request, sizeof(request),
             "{\"claimed_gid\":%010u,\"claimed_pid\":%d,\"claimed_uid\":%u,\"confinement_code\":\"" D9_CONFINEMENT_CODE "\",\"operation_nonce\":\"%s\",\"request_digest_sha256\":\"%s\",\"type\":\"hello\"}",
             claimed_gid, claimed_pid, claimed_uid, nonce, request_digest);
  } else {
    const char *claimed_operation_nonce = strcmp(scenario, "wrong_nonce") == 0
      ? "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      : nonce;
    const char *claimed_request_digest = strcmp(scenario, "wrong_request_digest") == 0
      ? "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      : request_digest;
    snprintf(request, sizeof(request),
             "{\"claimed_gid\":%u,\"claimed_pid\":%d,\"claimed_uid\":%u,\"confinement_code\":\"" D9_CONFINEMENT_CODE "\",\"operation_nonce\":\"%s\",\"request_digest_sha256\":\"%s\",\"type\":\"hello\"}",
             claimed_gid, claimed_pid, claimed_uid, claimed_operation_nonce, claimed_request_digest);
  }

  if (strcmp(scenario, "too_many_fds") == 0) {
    int fds[D9_MAX_ANCILLARY_FDS + 1U];
    size_t index;
    int send_result;
    for (index = 0; index < D9_MAX_ANCILLARY_FDS + 1U; index += 1U) {
      fds[index] = open("/dev/null", O_RDONLY | O_CLOEXEC);
      if (fds[index] < 0) {
        while (index > 0U) close(fds[--index]);
        close(socket_fd);
        return 2;
      }
    }
    {
      char ancillary[CMSG_SPACE(sizeof(fds))];
      struct iovec vector;
      struct msghdr message;
      struct cmsghdr *header;
      memset(&message, 0, sizeof(message));
      memset(ancillary, 0, sizeof(ancillary));
      vector.iov_base = request;
      vector.iov_len = strlen(request);
      message.msg_iov = &vector;
      message.msg_iovlen = 1;
      message.msg_control = ancillary;
      message.msg_controllen = sizeof(ancillary);
      header = CMSG_FIRSTHDR(&message);
      header->cmsg_level = SOL_SOCKET;
      header->cmsg_type = SCM_RIGHTS;
      header->cmsg_len = CMSG_LEN(sizeof(fds));
      memcpy(CMSG_DATA(header), fds, sizeof(fds));
      send_result = sendmsg(socket_fd, &message, MSG_NOSIGNAL) < 0 ? 2 : 0;
    }
    for (index = 0; index < D9_MAX_ANCILLARY_FDS + 1U; index += 1U) close(fds[index]);
    if (send_result != 0) {
      close(socket_fd);
      return send_result;
    }
    for (;;) pause();
  }

  if (install_peer_confinement() != 0) {
    close(socket_fd);
    return 2;
  }

  if (send(socket_fd, request, strlen(request), MSG_NOSIGNAL) != (ssize_t)strlen(request)) {
    close(socket_fd);
    return 2;
  }
  {
    struct received_packet response;
    char payload[D9_MAX_PACKET_BYTES + 1U];
    int cloexec;
    char contents[64] = {0};
    ssize_t content_length;
    if (wait_readable(socket_fd, D9_PEER_TIMEOUT_MS) != 1 ||
        receive_packet(socket_fd, payload, D9_MAX_PACKET_BYTES, &response) != 0 ||
        (response.flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || response.fd_count != grant_count) {
      close_received_fds(&response);
      close(socket_fd);
      return 2;
    }
    payload[response.length] = '\0';
    {
      size_t used = (size_t)snprintf(expected_response, sizeof(expected_response),
                                    "{\"descriptor_count\":%zu,\"descriptor_token\":\"%s\",\"descriptors\":[",
                                    grant_count, token);
      if (used >= sizeof(expected_response)) {
        close_received_fds(&response);
        close(socket_fd);
        return 2;
      }
      for (index = 0U; index < grant_count; index += 1U) {
        const int amount = snprintf(expected_response + used, sizeof(expected_response) - used,
                                    "%s{\"access_code\":\"%s\",\"ordinal\":%zu,\"runtime_role_code\":\"%s\",\"slot_code\":\"%s\"}",
                                    index == 0U ? "" : ",", grants[index].access_code, index,
                                    grants[index].runtime_role_code, grants[index].slot_code);
        if (amount < 0 || (size_t)amount >= sizeof(expected_response) - used) {
          close_received_fds(&response);
          close(socket_fd);
          return 2;
        }
        used += (size_t)amount;
      }
      if ((size_t)snprintf(expected_response + used, sizeof(expected_response) - used,
                           "],\"operation_nonce\":\"%s\",\"request_digest_sha256\":\"%s\",\"type\":\"descriptor\"}",
                           nonce, request_digest) >= sizeof(expected_response) - used) {
        close_received_fds(&response);
        close(socket_fd);
        return 2;
      }
    }
    if (strcmp(payload, expected_response) != 0) {
      close_received_fds(&response);
      close(socket_fd);
      return 2;
    }
    for (index = 0U; index < grant_count; index += 1U) {
      cloexec = fcntl(response.fds[index], F_GETFD);
      content_length = read(response.fds[index], contents, sizeof(contents));
      if (cloexec < 0 || (cloexec & FD_CLOEXEC) == 0 || content_length != (ssize_t)strlen(synthetic_descriptor_bytes) ||
          memcmp(contents, synthetic_descriptor_bytes, (size_t)content_length) != 0) {
        close_received_fds(&response);
        close(socket_fd);
        return 2;
      }
    }
    if (strcmp(scenario, "fork_escape") == 0) {
#ifdef __NR_fork
      (void)syscall(__NR_fork);
#else
      (void)syscall(__NR_clone3, NULL, 0U);
#endif
    }
    if (strcmp(scenario, "fd_transfer_escape") == 0) {
      (void)send_packet(socket_fd, "x", 1U, response.fds, 1U);
    }
    close_received_fds(&response);
  }

  snprintf(ack, sizeof(ack),
           "{\"descriptor_count\":%zu,\"descriptor_token\":\"%s\",\"operation_nonce\":\"%s\",\"request_digest_sha256\":\"%s\",\"status\":\"closed\",\"type\":\"descriptor_ack\"}",
           grant_count, token, nonce, request_digest);
  if (send(socket_fd, ack, strlen(ack), MSG_NOSIGNAL) != (ssize_t)strlen(ack)) {
    close(socket_fd);
    return 2;
  }
  if (strcmp(scenario, "replay") == 0 && send(socket_fd, ack, strlen(ack), MSG_NOSIGNAL) != (ssize_t)strlen(ack)) {
    close(socket_fd);
    return 2;
  }

  for (;;) pause();
}

static int lock_command(int argc, char **argv, bool hold) {
  int root_fd = -1;
  int lock_fd = -1;
  int result = 2;
  struct stat lock_status;
  if (argc != 4) {
    print_error_result("ARGUMENTS_INVALID");
    return 2;
  }
  root_fd = safe_open_root(argv[2]);
  if (root_fd < 0 || (lock_fd = safe_open_beneath(root_fd, argv[3], O_RDWR | O_CREAT, 0600)) < 0) {
    print_error_result("LOCK_OPEN_FAILED");
    goto cleanup;
  }
  if (fstat(lock_fd, &lock_status) != 0 || !S_ISREG(lock_status.st_mode) || lock_status.st_nlink != 1 ||
      (lock_status.st_uid != 0 && lock_status.st_uid != geteuid()) || (lock_status.st_mode & 0022) != 0) {
    print_error_result("LOCK_FILE_INVALID");
    goto cleanup;
  }
  if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      printf("{\"event\":\"lock\",\"status\":\"busy\"}\n");
      fflush(stdout);
      result = 3;
    } else {
      print_error_result("LOCK_FAILED");
    }
    goto cleanup;
  }
  printf("{\"event\":\"lock\",\"status\":\"acquired\",\"pid\":%ld}\n", (long)getpid());
  fflush(stdout);
  result = 0;
  if (hold) {
    char byte;
    while (read(STDIN_FILENO, &byte, 1U) > 0) {}
  }
cleanup:
  if (lock_fd >= 0) close(lock_fd);
  if (root_fd >= 0) close(root_fd);
  return result;
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  if (strcmp(argv[1], "probe") == 0) return probe_command();
  if (strcmp(argv[1], "broker") == 0) return broker_command(argc, argv);
  if (strcmp(argv[1], "synthetic-peer") == 0) return peer_command(argc, argv);
  if (strcmp(argv[1], "lock-hold") == 0) return lock_command(argc, argv, true);
  if (strcmp(argv[1], "lock-try") == 0) return lock_command(argc, argv, false);
  return 2;
}
