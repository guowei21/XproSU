/* GhostLock engine preload entry.
 *
 * The engine was written as a standalone PIE binary whose main() calls
 * run_exploit(). KSuRoot ships its payloads as LD_PRELOAD objects instead:
 * the root helper is exec'd with LD_PRELOAD=<this .so> and the whole run has
 * to happen before that process gets a chance to exit, so the constructor
 * blocks until run_exploit() returns.
 *
 * Two entry shapes:
 *   - LD_PRELOAD injection (helper process): run synchronously, then let the
 *     host program continue. A re-entrancy guard is exported into the
 *     environment so children that re-exec through the same LD_PRELOAD do not
 *     start a second engine instance.
 *   - dlopen (manager UI process): do NOT block the caller's main thread; run
 *     on a detached thread instead.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int run_exploit(int argc, char **argv);

static void *gl_preload_main(void *arg) {
  (void)arg;
  run_exploit(0, NULL);
  return NULL;
}

/* KSuRoot ships payloads without any environment handshake: the manager only
 * sets LD_PRELOAD. Two defaults therefore have to come from here.
 *
 *   route: the engine picks TCP whenever the target kernel reports a compact
 *          waiter. That path wedges this device, so mcast has to be the
 *          default unless the caller explicitly asked for something else.
 *   home:  the engine writes .ghostlock_root.sh and the ksu log there. Hand it
 *          the first writable directory it can actually use. */
static void gl_apply_default_env(void) {
  if (!getenv("GHOSTLOCK_ROUTE")) {
    const char *mcast = getenv("GHOSTLOCK_MCAST_ROUTE");
    if (!mcast || !mcast[0]) setenv("GHOSTLOCK_ROUTE", "mcast", 1);
  }
  if (!getenv("GHOSTLOCK_HOME")) {
    const char *home = getenv("TMPDIR");
    if (!home || !home[0] || access(home, W_OK) != 0) home = "/data/local/tmp";
    if (access(home, W_OK) == 0) setenv("GHOSTLOCK_HOME", home, 1);
  }
}

static int started_by_preload(void) {
  const char *preload = getenv("LD_PRELOAD");
  if (!preload || !preload[0]) return 0;
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

  pthread_t th;
  int rc = pthread_create(&th, have_attr ? &attr : NULL, gl_preload_main, NULL);
  if (have_attr) pthread_attr_destroy(&attr);
  if (rc != 0) {
    gl_preload_main(NULL); /* no thread available: run inline */
    return;
  }
  if (started_by_preload()) {
    pthread_join(th, NULL); /* helper must not exit before the engine is done */
  } else {
    pthread_detach(th);
  }
}