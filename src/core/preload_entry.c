/* GhostLock engine preload entry.
 *
 * The engine was written as a standalone PIE binary whose main() calls
 * run_exploit(). KSuRoot ships its payloads as LD_PRELOAD objects instead:
 * the root helper is exec'd with LD_PRELOAD=<this .so> and the whole run has
 * to happen before that process gets a chance to exit, so the constructor
 * blocks until run_exploit() returns.
 *
 * Output plumbing (this file owns it):
 *   - Everything the engine prints is mirrored to <GHOSTLOCK_HOME>/_gl_run.log,
 *     so a wedged device still leaves a complete transcript on disk after the
 *     reboot. The manager pipe gets a best-effort copy (non-blocking): a
 *     manager that stops draining must never block the engine.
 *   - Only this process keeps the manager pipe open. Forked children (root
 *     helper, root shell worker, ksud chain) call gl_preload_child_cleanup()
 *     so a parked daemon cannot hold the write end and stall the install UI
 *     waiting for EOF.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern int run_exploit(int argc, char **argv);

static pthread_mutex_t g_done_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_done_cv = PTHREAD_COND_INITIALIZER;
static int g_done = 0;
static int g_engine_rc = -1;

/* manager stdout (original fd 1) and the on-disk transcript */
static int g_app_out = -1;
static int g_run_log = -1;

static void gl_write_all(int fd, const char *s, size_t n, int timeout_ms) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, s + off, n - off);
    if (w > 0) {
      off += (size_t)w;
      continue;
    }
    if (w < 0 && (errno == EAGAIN || errno == EINTR)) {
      struct pollfd pfd;
      pfd.fd = fd;
      pfd.events = POLLOUT;
      pfd.revents = 0;
      if (timeout_ms <= 0 || poll(&pfd, 1, timeout_ms) <= 0) return; /* drop */
      continue;
    }
    return;
  }
}

/* Runs inside the engine process: copy whatever the engine writes to our pipe
 * into the transcript and, best effort, into the manager's pipe. */
static void *gl_tee_main(void *arg) {
  int rd = (int)(intptr_t)arg;
  char buf[8192];
  for (;;) {
    ssize_t n = read(rd, buf, sizeof buf);
    if (n <= 0) break;
    if (g_run_log >= 0) {
      gl_write_all(g_run_log, buf, (size_t)n, 2000);
      /* f2fs rolls back to the last checkpoint after a panic, which turns a
       * buffered transcript into a file full of NULs. Make every line
       * durable before the engine is allowed to touch the kernel again. */
      fdatasync(g_run_log);
    }
    if (g_app_out >= 0) gl_write_all(g_app_out, buf, (size_t)n, 200);
  }
  close(rd);
  return NULL;
}

static void gl_start_capture(void) {
  const char *home = getenv("GHOSTLOCK_HOME");
  if (!home || !home[0]) home = "/data/local/tmp";
  char path[256];
  snprintf(path, sizeof path, "%s/_gl_run.log", home);
  g_run_log = open(path, O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0666);

  int p[2];
  if (pipe(p) != 0) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return;
  }
  g_app_out = dup(STDOUT_FILENO);
  if (g_app_out >= 0) {
    int fl = fcntl(g_app_out, F_GETFL, 0);
    if (fl >= 0) fcntl(g_app_out, F_SETFL, fl | O_NONBLOCK);
  }
  dup2(p[1], STDOUT_FILENO);
  dup2(p[1], STDERR_FILENO);
  if (p[1] > STDERR_FILENO) close(p[1]);

  pthread_t th;
  if (pthread_create(&th, NULL, gl_tee_main, (void *)(intptr_t)p[0]) == 0)
    pthread_detach(th);
  else
    close(p[0]);

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

/* Called from forked children before they exec the root shell / park / start
 * ksud: drop both the manager pipe and the transcript handle. */
void gl_preload_child_cleanup(void) {
  if (g_app_out > STDERR_FILENO) {
    close(g_app_out);
    g_app_out = -1;
  }
  if (g_run_log > STDERR_FILENO) {
    close(g_run_log);
    g_run_log = -1;
  }
}

static void gl_banner(void) {
  char b[192];
  time_t now = time(NULL);
  struct tm tmv;
  localtime_r(&now, &tmv);
  int n = snprintf(b, sizeof b,
                   "\n===== ghostlock preload pid=%d %04d-%02d-%02d %02d:%02d:%02d "
                   "home=%s =====\n",
                   (int)getpid(), tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                   tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                   getenv("GHOSTLOCK_HOME") ? getenv("GHOSTLOCK_HOME") : "?");
  if (n <= 0) return;
  if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
  if (g_run_log >= 0) gl_write_all(g_run_log, b, (size_t)n, 2000);
  if (g_app_out >= 0) gl_write_all(g_app_out, b, (size_t)n, 200);
}

static void gl_emit_manager_markers(int rc) {
  if (rc != 0) return;
  static const char m[] = "[*] exploit completed\n[*] done=1 root=1\n";
  if (g_run_log >= 0) gl_write_all(g_run_log, m, sizeof m - 1, 2000);
  if (g_app_out >= 0) gl_write_all(g_app_out, m, sizeof m - 1, 2000);
}

static void *gl_preload_main(void *arg) {
  (void)arg;
  int rc = run_exploit(0, NULL);
  gl_emit_manager_markers(rc);
  pthread_mutex_lock(&g_done_lock);
  g_engine_rc = rc;
  g_done = 1;
  pthread_cond_broadcast(&g_done_cv);
  pthread_mutex_unlock(&g_done_lock);
  return NULL;
}

/* KSuRoot ships payloads without any environment handshake: the manager only
 * sets LD_PRELOAD. Two defaults therefore have to come from here.
 *
 *   route: the engine picks TCP whenever the target kernel reports a compact
 *          waiter. That path wedges this device, so mcast has to be the
 *          default unless the caller explicitly asked for something else.
 *   home:  the engine writes .ghostlock_root.sh and the ksu log there. Hand it
 *          the first writable directory it can actually use.
 *   cores: every crash we reproduced ran with the default 0/1 pair, and three
 *          consecutive runs pinned to 6/7 finished with no oops at all, so the
 *          wide cores become the default on >=8-cpu layouts. The engine still
 *          falls back to 0/1 when this device's cpuset does not contain them. */
static void gl_apply_default_env(void) {
  if (!getenv("GHOSTLOCK_ROUTE")) {
    const char *mcast = getenv("GHOSTLOCK_MCAST_ROUTE");
    if (!mcast || !mcast[0]) setenv("GHOSTLOCK_ROUTE", "mcast", 1);
  }
  /* the manager installs KernelSU itself once it has root; let it, instead of
   * racing the engine's own ksud handover. */
  if (!getenv("GHOSTLOCK_DISABLE_MODULES"))
    setenv("GHOSTLOCK_DISABLE_MODULES", "1", 1);
  if (!getenv("GHOSTLOCK_HOME")) {
    const char *home = getenv("TMPDIR");
    if (!home || !home[0] || access(home, W_OK) != 0) home = "/data/local/tmp";
    if (access(home, W_OK) == 0) setenv("GHOSTLOCK_HOME", home, 1);
  }
  if (!getenv("GHOSTLOCK_CORE") && !getenv("GHOSTLOCK_CONSUMER_CORE") &&
      sysconf(_SC_NPROCESSORS_CONF) >= 8) {
    setenv("GHOSTLOCK_CORE", "6", 1);
    setenv("GHOSTLOCK_CONSUMER_CORE", "7", 1);
  }
}

/* True when this object was injected through LD_PRELOAD, i.e. the host process
 * will not survive us returning early. The manager's own copy lands on disk as
 * payload.so, so matching a name pattern is not enough: ask the linker for the
 * path we were actually loaded from and look for that basename. */
static int started_by_preload(void) {
  const char *preload = getenv("LD_PRELOAD");
  if (!preload || !preload[0]) return 0;
  Dl_info info;
  if (dladdr((void *)&gl_preload_main, &info) && info.dli_fname) {
    const char *base = strrchr(info.dli_fname, '/');
    base = base ? base + 1 : info.dli_fname;
    if (base[0] && strstr(preload, base)) return 1;
  }
  return strstr(preload, "libghostlock") != NULL ||
         strstr(preload, "libksu_") != NULL;
}

__attribute__((constructor)) static void gl_preload_ctor(void) {
  const char *guard = getenv("GHOSTLOCK_PRELOAD_ACTIVE");
  if (guard && guard[0] == '1') return;
  setenv("GHOSTLOCK_PRELOAD_ACTIVE", "1", 1);
  gl_apply_default_env();

  pthread_attr_t attr;
  int have_attr = pthread_attr_init(&attr) == 0;
  if (have_attr) pthread_attr_setstacksize(&attr, (size_t)8 << 20);

  gl_start_capture();
  gl_banner();

  pthread_t th;
  int rc = pthread_create(&th, have_attr ? &attr : NULL, gl_preload_main, NULL);
  if (have_attr) pthread_attr_destroy(&attr);
  if (rc != 0) {
    gl_preload_main(NULL); /* no thread available: run inline */
    return;
  }
  if (started_by_preload()) {
    /* The helper must not exit before the engine is done, but it must also
     * never hang forever: wait on a bounded budget and then let the host
     * continue with whatever state the engine reached. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 240;
    pthread_mutex_lock(&g_done_lock);
    while (!g_done) {
      if (pthread_cond_timedwait(&g_done_cv, &g_done_lock, &ts) != 0) break;
    }
    pthread_mutex_unlock(&g_done_lock);
    pthread_detach(th);
  } else {
    pthread_detach(th);
  }
}
