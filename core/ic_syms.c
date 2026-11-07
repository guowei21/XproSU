/*
 * ic_syms.c -- on-device kernel image -> symbol table for the IC timer LPE.
 *
 * The recovery heuristics are a C port of the project's kallsyms_py.py
 * (itself a port of ghostlock-extract's kallsyms_finder.rs).  It finds the
 * token table, the marker table, the compressed name stream and the address
 * table inside a raw ARM64 Image, then decodes the entries.  Android boot
 * images are unwrapped first; the kernel payload is decompressed when it is
 * lz4-legacy, gzip (if built with zlib) or already a raw Image.
 *
 * vmlinux ELF and text System.map files take the direct path.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ic_syms.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(IC_SYMS_HAVE_ZLIB)
#include <zlib.h>
#endif

#define ALIGN8 8u
#define TOKEN_COUNT 256
#define TOKEN_INDEX_SIZE (TOKEN_COUNT * 2)
#define MAX_TOKEN_LEN 256
#define MARKER_SEARCH_WINDOW (4u * 1024 * 1024)
#define NAME_TAIL_SEARCH 0x40000u
#define MIN_MARKERS 8
#define MAX_MARKERS 4096
#define MAX_NAME_EXPANDED 4096

const char *const ic_syms_required[] = {
	"__filemap_fdatawait_range",
	"__vm_munmap",
	"__wait_one_discard_bio",
	"do_checkpoint",
	"do_exit",
	"f2fs_issue_checkpoint",
	"f2fs_wait_on_node_pages_writeback",
	"filemap_read",
	"msleep",
	"rcu_gp_fqs_loop",
	"rcu_gp_kthread",
	"runqueues",
	"synchronize_rcu_expedited",
	"ufshcd_delay_us",
	"worker_thread",
	"futex_wait_queue",
	"futex_wait",
	"do_futex",
	"pipe_read",
	"pipe_write",
	"do_epoll_wait",
	"schedule_timeout",
	"io_schedule",
	"msleep_interruptible",
	"wait_for_completion",
	"wait_for_completion_interruptible",
	"mutex_lock",
	"__mutex_lock_slowpath",
	"down",
	"down_read",
	"kthread",
	"kthreadd",
	"kthread_worker_fn",
	"rescuer_thread",
	"flush_work",
	"cancel_work_sync",
	"jbd2_log_wait_commit",
	"jbd2_journal_commit_transaction",
	"f2fs_balance_fs",
	"f2fs_write_checkpoint",
	"submit_bio_wait",
	"vfs_read",
	"vfs_write",
	"ksys_read",
	"ksys_write",
	"sock_recvmsg",
	"unix_stream_recvmsg",
	"tcp_recvmsg",
	"n_tty_read",
	"binder_thread_read",
	"binder_ioctl",
	"do_sys_poll",
	"do_select",
	"core_sys_select",
	"do_group_exit",
	"vm_munmap",
	"mmap_region",
	"filemap_fdatawait_range",
	"synchronize_rcu",
	"io_wq_submit_work",
	"__flush_workqueue",
	"drain_workqueue",
	/* targets (always the last four) */
	"__tracepoint_sys_exit",
	"selinux_state",
	"init_user_ns",
	"init_cred",
	"root_user",
	"init_ucounts",
	"init_groups",
	NULL
};

const int ic_syms_required_n =
	(int)(sizeof(ic_syms_required) / sizeof(ic_syms_required[0])) - 1;

/* ------------------------------------------------------------------ misc */

static uint16_t rd16(const unsigned char *p)
{
	return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int32_t rdi32(const unsigned char *p)
{
	return (int32_t)rd32(p);
}

static uint64_t rd64(const unsigned char *p)
{
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static uint32_t align_up(uint32_t v, uint32_t a)
{
	return (v + a - 1) & ~(a - 1);
}

static const unsigned char *ic_memmem(const unsigned char *hay, size_t hlen,
				      const unsigned char *needle, size_t nlen)
{
	size_t i;

	if (!nlen || nlen > hlen)
		return NULL;
	for (i = 0; i + nlen <= hlen; i++)
		if (hay[i] == needle[0] && !memcmp(hay + i, needle, nlen))
			return hay + i;
	return NULL;
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);

	if (!p) {
		fprintf(stderr, "[syms] out of memory (%zu bytes)\n", n);
		exit(3);
	}
	return p;
}

static unsigned char *read_file(const char *path, size_t *lenp, size_t maxlen)
{
	FILE *f = fopen(path, "rb");
	unsigned char *b;
	long sz;

	if (!f) {
		fprintf(stderr, "[syms] cannot open %s: %s\n", path,
			strerror(errno));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0) {
		fclose(f);
		fprintf(stderr, "[syms] cannot size %s\n", path);
		return NULL;
	}
	if ((size_t)sz > maxlen) {
		fclose(f);
		fprintf(stderr, "[syms] %s is too large (%ld bytes)\n", path, sz);
		return NULL;
	}
	rewind(f);
	b = xmalloc((size_t)sz + 1);
	if (sz && fread(b, 1, (size_t)sz, f) != (size_t)sz) {
		fclose(f);
		free(b);
		fprintf(stderr, "[syms] short read on %s\n", path);
		return NULL;
	}
	fclose(f);
	b[sz] = 0;
	*lenp = (size_t)sz;
	return b;
}

int ic_syms_is_required(const char *name)
{
	int i;

	for (i = 0; i < ic_syms_required_n; i++)
		if (!strcmp(ic_syms_required[i], name))
			return 1;
	/* Optional extra symbols: emitted when the image has them, ignored
	 * when it does not; the four targets above remain the only hard
	 * requirement. */
	if (!strcmp(name, "sig_enforce") ||
	    !strcmp(name, "module_notify_list") ||
	    !strcmp(name, "panic_on_warn"))
		return 1;
	return 0;
}

int ic_syms_banner_release(const unsigned char *img, size_t len,
			   char *out, size_t outlen)
{
	static const char key[] = "Linux version ";
	const unsigned char *p = img;
	size_t left = len;

	if (!outlen)
		return 0;
	while (left >= sizeof(key) - 1) {
		const unsigned char *q = ic_memmem(p, left,
						   (const unsigned char *)key,
						   sizeof(key) - 1);
		size_t n = 0;

		if (!q)
			break;
		q += sizeof(key) - 1;
		left -= (size_t)(q - p);
		p = q;
		while (n < left && n + 1 < outlen &&
		       q[n] != ' ' && q[n] != '\n' && q[n] != '\r' &&
		       q[n] != '\0') {
			out[n] = (char)q[n];
			n++;
		}
		out[n] = '\0';
		if (n > 0 && strchr(out, '.'))
			return 1;
	}
	return 0;
}

static int is_arm64_addr(uint64_t a)
{
	return (a >> 48) == 0xffff && (a & 0xfff) == 0;
}

static uint64_t image_size_of(const unsigned char *img, size_t len)
{
	if (len >= 64 && !memcmp(img + 0x38, "ARM\x64", 4)) {
		uint64_t s = rd64(img + 0x10);

		if (s)
			return s;
	}
	return (uint64_t)len;
}

/* ------------------------------------------------------ token/name tables */

struct token_tab {
	const unsigned char *tok[TOKEN_COUNT];
	uint32_t table_off;
	uint32_t index_off;
};

struct span {
	uint32_t pos;
	uint32_t len;
};

struct name_block {
	uint32_t num_syms_off;
	uint32_t count;
	struct span *spans;
	uint32_t *name_off;
	unsigned char *kinds;
	char *names;
	size_t names_len;
	size_t names_cap;
};

static void free_name_block(struct name_block *nb)
{
	free(nb->spans);
	free(nb->name_off);
	free(nb->kinds);
	free(nb->names);
	memset(nb, 0, sizeof(*nb));
}

static int parse_token_table_at(const unsigned char *img, size_t len,
				uint32_t start, uint32_t digit_off,
				struct token_tab *out)
{
	static const char singles[] = "0123456789_abcdefghijklmnopqrstuvwxyzT";
	uint32_t starts[TOKEN_COUNT];
	uint16_t offs[TOKEN_COUNT];
	uint32_t pos = start;
	uint32_t i;

	if (start & (ALIGN8 - 1))
		return 0;
	for (i = 0; i < TOKEN_COUNT; i++) {
		uint32_t end = pos + MAX_TOKEN_LEN + 1;
		const unsigned char *z;
		uint32_t l, k;

		if (end > len)
			end = (uint32_t)len;
		if (pos >= end)
			return 0;
		z = memchr(img + pos, 0, end - pos);
		if (!z)
			return 0;
		l = (uint32_t)(z - (img + pos));
		if (!l)
			return 0;
		for (k = 0; k < l; k++)
			if (img[pos + k] < 0x20 || img[pos + k] > 0x7e)
				return 0;
		starts[i] = pos;
		offs[i] = (uint16_t)(pos - start);
		out->tok[i] = img + pos;
		pos += l + 1;
		if (pos > len)
			return 0;
	}
	if (starts[(unsigned char)'0'] != digit_off)
		return 0;
	for (i = 0; singles[i]; i++) {
		unsigned char c = (unsigned char)singles[i];

		if (out->tok[c][0] != c || out->tok[c][1] != 0)
			return 0;
	}
	{
		uint32_t idx = align_up(pos, ALIGN8);
		uint32_t k;

		for (k = pos; k < idx; k++)
			if (img[k])
				return 0;
		if (idx + TOKEN_INDEX_SIZE > len)
			return 0;
		for (i = 0; i < TOKEN_COUNT; i++) {
			if (offs[i] > 0xffff)
				return 0;
			if (rd16(img + idx + i * 2) != offs[i])
				return 0;
		}
		out->table_off = start;
		out->index_off = idx;
	}
	return 1;
}

static int find_token_tables(const unsigned char *img, size_t len,
			     struct token_tab *tabs, int cap)
{
	static const unsigned char needle[20] = {
		'0', 0, '1', 0, '2', 0, '3', 0, '4', 0,
		'5', 0, '6', 0, '7', 0, '8', 0, '9', 0
	};
	size_t from = 0;
	int n = 0;

	while (from + sizeof(needle) <= len) {
		const unsigned char *hit = ic_memmem(img + from, len - from,
						     needle, sizeof(needle));
		uint32_t digit_off, earliest, start;

		if (!hit)
			break;
		digit_off = (uint32_t)(hit - img);
		earliest = digit_off > (uint32_t)('0' * (MAX_TOKEN_LEN + 1))
				   ? digit_off -
					     (uint32_t)('0' * (MAX_TOKEN_LEN + 1))
				   : 0;
		start = align_up(earliest, ALIGN8);
		for (; start <= digit_off; start += ALIGN8)
			if (n < cap &&
			    parse_token_table_at(img, len, start, digit_off,
						 &tabs[n]))
				n++;
		from = (size_t)digit_off + 1;
	}
	return n;
}

static int read_markers(const unsigned char *img, size_t len, uint32_t start,
			uint32_t limit, uint32_t *markers)
{
	uint32_t first, second, pos;
	int n = 0;

	if ((start & (ALIGN8 - 1)) || start + 8 > limit || start + 8 > len)
		return 0;
	first = rd32(img + start);
	second = rd32(img + start + 4);
	if (first != 0 || second < 0x200 || second > 0x40000)
		return 0;
	markers[n++] = first;
	markers[n++] = second;
	pos = start + 8;
	while (n < MAX_MARKERS && pos + 4 <= limit && pos + 4 <= len) {
		uint32_t v = rd32(img + pos);
		uint32_t delta = v - markers[n - 1];

		if (delta < 0x200 || delta > 0x40000)
			break;
		markers[n++] = v;
		pos += 4;
	}
	return n >= MIN_MARKERS ? n : 0;
}

static int parse_name_spans(const unsigned char *img, size_t len,
			    uint32_t names_off, uint32_t count,
			    uint32_t markers_off, const uint32_t *markers,
			    int nmarkers, int uleb, struct span *spans)
{
	uint32_t pos = names_off;
	uint32_t index;

	if (!count || nmarkers != (int)((count + 255) / 256))
		return 0;
	for (index = 0; index < count; index++) {
		uint32_t length;

		if ((index & 255) == 0 &&
		    pos - names_off != markers[index / 256])
			return 0;
		if (pos >= markers_off || pos >= len)
			return 0;
		length = img[pos++];
		if (uleb && (length & 0x80)) {
			unsigned char high;

			if (pos >= markers_off || pos >= len)
				return 0;
			high = img[pos++];
			if (high & 0x80)
				return 0;
			length = (length & 0x7f) | ((uint32_t)high << 7);
		}
		if (!length || length > 0x3fff || pos + length > markers_off)
			return 0;
		spans[index].pos = pos;
		spans[index].len = length;
		pos += length;
	}
	if (align_up(pos, ALIGN8) != markers_off)
		return 0;
	for (; pos < markers_off; pos++)
		if (img[pos])
			return 0;
	return 1;
}

static int sym_kind_ok(unsigned char k)
{
	static const char types[] = "aAbBcCdDeEfFgGiInNpPrRsStTuUvVwW?-";

	return strchr(types, k) != NULL;
}

static int name_block_append(struct name_block *nb, const char *s, size_t l)
{
	if (nb->names_len + l + 1 > nb->names_cap) {
		size_t cap = nb->names_cap ? nb->names_cap * 2 : 65536;

		while (cap < nb->names_len + l + 1)
			cap *= 2;
		nb->names = realloc(nb->names, cap);
		if (!nb->names) {
			fprintf(stderr, "[syms] out of memory (names)\n");
			return 0;
		}
		nb->names_cap = cap;
	}
	memcpy(nb->names + nb->names_len, s, l);
	nb->names[nb->names_len + l] = 0;
	nb->names_len += l + 1;
	return 1;
}

/* Decode every name; `nb->spans` is owned by the caller and transferred on
 * success.  Allocates name_off/kinds/names. */
static int decode_names(const unsigned char *img, size_t len,
			const struct token_tab *tab, struct name_block *nb)
{
	char expanded[MAX_NAME_EXPANDED + 1];
	uint32_t i;
	int have_text = 0, have_end = 0, have_load = 0;

	nb->name_off = xmalloc(sizeof(*nb->name_off) * nb->count);
	nb->kinds = xmalloc(nb->count);
	if (getenv("IC_SYMS_DEBUG"))
		fprintf(stderr, "[dbg] decode_names enter count=%u spans=%p\n",
			nb->count, (void *)nb->spans);
	for (i = 0; i < nb->count; i++) {
		const struct span *sp = &nb->spans[i];
		size_t elen = 0;
		uint32_t k;
		const char *name;
		size_t nlen;

		if (sp->pos + sp->len > len)
			goto bad;
		for (k = 0; k < sp->len; k++) {
			unsigned char t = img[sp->pos + k];
			const unsigned char *tok = tab->tok[t];
			size_t tl = strlen((const char *)tok);

			if (elen + tl > MAX_NAME_EXPANDED)
				goto bad;
			memcpy(expanded + elen, tok, tl);
			elen += tl;
		}
		if (!elen || !sym_kind_ok((unsigned char)expanded[0]))
			goto bad;
		name = expanded + 1;
		nlen = elen - 1;
		if (!nlen)
			goto bad;
		for (k = 0; k < nlen; k++)
			if ((unsigned char)name[k] < 0x21 ||
			    (unsigned char)name[k] > 0x7e)
				goto bad;
		nb->kinds[i] = (unsigned char)expanded[0];
		nb->name_off[i] = (uint32_t)nb->names_len;
		if (!name_block_append(nb, name, nlen))
			goto bad;
		if (nlen == 5 && !memcmp(name, "_text", 5))
			have_text = 1;
		else if (nlen == 4 && !memcmp(name, "_end", 4))
			have_end = 1;
		else if (nlen == 11 && !memcmp(name, "load_module", 11))
			have_load = 1;
	}
	if (!have_text || !have_end || !have_load)
		goto bad;
	if (getenv("IC_SYMS_DEBUG"))
		fprintf(stderr,
			"[dbg] decode_names ok count=%u len=%zu text=%d end=%d load=%d\n",
			nb->count, nb->names_len, have_text, have_end, have_load);
	return 1;
bad:
	free(nb->name_off);
	free(nb->kinds);
	free(nb->names);
	nb->name_off = NULL;
	nb->kinds = NULL;
	nb->names = NULL;
	nb->names_len = nb->names_cap = 0;
	return 0;
}

/* Fills `addrs` (count entries) and returns 1 when the table is sane. */
static int decode_addresses(const unsigned char *img, size_t len,
			    uint64_t image_size, const struct name_block *nb,
			    uint32_t offsets_off, uint32_t relative_base_off,
			    uint64_t *addrs, uint64_t *text_out,
			    uint64_t *end_out)
{
	uint32_t i;
	uint64_t rel;
	int negative = 0, text_n = 0, end_n = 0;
	uint64_t text = 0, end = 0;
	size_t ordinary = 0, in_image = 0;

	if (relative_base_off < offsets_off + nb->count * 4 ||
	    (uint64_t)relative_base_off + 8 > len) {
		if (getenv("IC_SYMS_DEBUG"))
			fprintf(stderr, "[dbg] addr: range\n");
		return 0;
	}
	for (i = offsets_off + nb->count * 4; i < relative_base_off; i++)
		if (img[i]) {
			if (getenv("IC_SYMS_DEBUG"))
				fprintf(stderr, "[dbg] addr: padding byte at %#x\n", i);
			return 0;
		}
	rel = rd64(img + relative_base_off);
	if (!is_arm64_addr(rel)) {
		if (getenv("IC_SYMS_DEBUG"))
			fprintf(stderr, "[dbg] addr: rel %#llx not arm64\n",
				(unsigned long long)rel);
		return 0;
	}
	for (i = 0; i < nb->count; i++)
		if (rdi32(img + offsets_off + i * 4) < 0)
			negative++;
	if (negative * 2 >= (int)nb->count) {
		for (i = 0; i < nb->count; i++) {
			int32_t v = rdi32(img + offsets_off + i * 4);

			addrs[i] = v < 0 ? rel - 1 - (uint64_t)(int64_t)v
					 : (uint64_t)(uint32_t)v;
		}
	} else {
		for (i = 0; i < nb->count; i++)
			addrs[i] = rel + (uint32_t)rd32(img + offsets_off + i * 4);
	}
	for (i = 1; i < nb->count; i++)
		if (addrs[i] < addrs[i - 1]) {
			if (getenv("IC_SYMS_DEBUG"))
				fprintf(stderr,
					"[dbg] addr: not sorted at %u (%#llx < %#llx)\n",
					i, (unsigned long long)addrs[i],
					(unsigned long long)addrs[i - 1]);
			return 0;
		}
	for (i = 0; i < nb->count; i++) {
		const char *name = nb->names + nb->name_off[i];

		if (!strcmp(name, "_text")) {
			text_n++;
			text = addrs[i];
		} else if (!strcmp(name, "_end")) {
			end_n++;
			end = addrs[i];
		}
	}
	if (text_n != 1 || end_n != 1 || text != rel || end - text != image_size) {
		if (getenv("IC_SYMS_DEBUG"))
			fprintf(stderr,
				"[dbg] addr: text_n=%d end_n=%d text=%#llx rel=%#llx end=%#llx image_size=%#llx\n",
				text_n, end_n, (unsigned long long)text,
				(unsigned long long)rel, (unsigned long long)end,
				(unsigned long long)image_size);
		return 0;
	}
	for (i = 0; i < nb->count; i++) {
		unsigned char k = nb->kinds[i];

		if (k == 'A' || k == 'a' || !addrs[i])
			continue;
		ordinary++;
		if (addrs[i] >= text && addrs[i] <= end)
			in_image++;
	}
	if (!ordinary || in_image * 100 < ordinary * 90) {
		if (getenv("IC_SYMS_DEBUG"))
			fprintf(stderr, "[dbg] addr: ordinary=%zu in=%zu\n",
				ordinary, in_image);
		return 0;
	}
	*text_out = text;
	*end_out = end;
	return 1;
}

struct recovered {
	struct name_block nb;
	uint64_t *addrs;
	uint64_t text;
	uint64_t end;
	uint64_t fingerprint;
	int valid;
};

static void try_one_name_block(const unsigned char *img, size_t len,
			       uint64_t image_size,
			       const struct token_tab *tab,
			       struct recovered *best, int *ambiguous,
			       uint32_t num_syms_off, uint32_t names_off,
			       uint32_t markers_off, uint32_t count,
			       const uint32_t *markers, int nmarkers)
{
	uint32_t old_rel = num_syms_off - ALIGN8;
	uint32_t old_off = old_rel - align_up(count * 4, ALIGN8);
	uint32_t new_off = align_up(tab->index_off + TOKEN_INDEX_SIZE, ALIGN8);
	uint32_t new_rel = align_up(new_off + count * 4, ALIGN8);
	uint32_t layouts[2][2] = { { old_off, old_rel }, { new_off, new_rel } };
	int li;

	for (li = 0; li < 2 && !*ambiguous; li++) {
		int uleb;

		for (uleb = 1; uleb >= 0 && !*ambiguous; uleb--) {
			struct name_block nb;
			struct span *spans = xmalloc(sizeof(*spans) * count);
			uint64_t *addrs = xmalloc(sizeof(*addrs) * count);
			uint64_t t = 0, e = 0;

			memset(&nb, 0, sizeof(nb));
			nb.count = count;
			nb.num_syms_off = num_syms_off;
			if (!parse_name_spans(img, len, names_off, count,
					      markers_off, markers, nmarkers,
					      uleb, spans)) {
				if (getenv("IC_SYMS_DEBUG"))
					fprintf(stderr,
						"[dbg] spans fail li=%d uleb=%d count=%u nm=%d\n",
						li, uleb, count, nmarkers);
				free(spans);
				free(addrs);
				continue;
			}
			nb.spans = spans;
			if (!decode_names(img, len, tab, &nb)) {
				/* decode_names frees only its own arrays */
				free(spans);
				free(addrs);
				continue;
			}
			if (getenv("IC_SYMS_DEBUG") && nb.count > 3)
				fprintf(stderr,
					"[dbg] names: len=%zu off=%u/%u/%u/%u: '%s' '%s' '%s' '%s'\n",
					nb.names_len, nb.name_off[0],
					nb.name_off[1], nb.name_off[2],
					nb.name_off[3],
					nb.names + nb.name_off[0],
					nb.names + nb.name_off[1],
					nb.names + nb.name_off[2],
					nb.names + nb.name_off[3]);
			if (!decode_addresses(img, len, image_size, &nb,
					      layouts[li][0], layouts[li][1],
					      addrs, &t, &e)) {
				if (getenv("IC_SYMS_DEBUG"))
					fprintf(stderr,
						"[dbg] addrs fail li=%d uleb=%d off=%#x rel=%#x\n",
						li, uleb, layouts[li][0],
						layouts[li][1]);
				free_name_block(&nb);
				free(addrs);
				continue;
			}
			{
				uint64_t fp = t ^ (e << 1) ^
					      ((uint64_t)count << 2);

				if (!best->valid) {
					best->nb = nb;
					best->addrs = addrs;
					best->text = t;
					best->end = e;
					best->fingerprint = fp;
					best->valid = 1;
				} else {
					if (fp != best->fingerprint)
						*ambiguous = 1;
					free_name_block(&nb);
					free(addrs);
				}
			}
		}
	}
}

static int recover_kallsyms(const unsigned char *img, size_t len,
			    struct recovered *out)
{
	struct token_tab tabs[8];
	uint64_t image_size = image_size_of(img, len);
	int ntabs, ti, ambiguous = 0;

	memset(out, 0, sizeof(*out));
	ntabs = find_token_tables(img, len, tabs, 8);
	if (!ntabs) {
		fprintf(stderr, "[syms] no kallsyms token table found\n");
		return 0;
	}
	fprintf(stderr, "[syms] token tables: %d\n", ntabs);
	if (getenv("IC_SYMS_DEBUG"))
		for (ti = 0; ti < ntabs; ti++)
			fprintf(stderr, "[dbg] token[%d] off=%#x idx=%#x\n",
				ti, tabs[ti].table_off, tabs[ti].index_off);
	for (ti = 0; ti < ntabs && !ambiguous; ti++) {
		const struct token_tab *tab = &tabs[ti];
		uint32_t lower = tab->table_off > MARKER_SEARCH_WINDOW
					 ? tab->table_off - MARKER_SEARCH_WINDOW
					 : 0;
		uint32_t pos;

		for (pos = align_up(lower, ALIGN8);
		     pos + 8 <= tab->table_off && !ambiguous; pos += ALIGN8) {
			uint32_t markers[MAX_MARKERS];
			int nmarkers = read_markers(img, len, pos,
						    tab->table_off, markers);
			uint32_t min_count, max_count;
			int64_t approx_names, search_start, nso;

			if (!nmarkers)
				continue;
			min_count = (uint32_t)(nmarkers - 1) * 256 + 1;
			max_count = (uint32_t)nmarkers * 256;
			approx_names = (int64_t)pos - markers[nmarkers - 1];
			if (approx_names < 0)
				continue;
			search_start = approx_names - (int64_t)NAME_TAIL_SEARCH;
			if (search_start < 0)
				search_start = 0;
			nso = approx_names - (approx_names % ALIGN8);
			for (;;) {
				uint32_t count = 0;
				int padding_zero = 0;

				if (nso + 8 <= (int64_t)len) {
					count = rd32(img + nso);
					padding_zero = rd32(img + nso + 4) == 0;
				}
				if (count >= min_count && count <= max_count &&
				    padding_zero) {
					if (getenv("IC_SYMS_DEBUG"))
						fprintf(stderr,
							"[dbg] candidate pos=%#x nso=%#x count=%u nm=%d\n",
							pos, (uint32_t)nso,
							count, nmarkers);
					try_one_name_block(img, len, image_size,
							   tab, out, &ambiguous,
							   (uint32_t)nso,
							   (uint32_t)nso + ALIGN8,
							   pos, count, markers,
							   nmarkers);
				}
				if (ambiguous ||
				    nso < search_start + (int64_t)ALIGN8)
					break;
				nso -= ALIGN8;
			}
		}
	}
	if (ambiguous) {
		fprintf(stderr, "[syms] ambiguous kallsyms layouts; refusing\n");
		free_name_block(&out->nb);
		free(out->addrs);
		out->addrs = NULL;
		return 0;
	}
	if (!out->valid) {
		fprintf(stderr, "[syms] no valid kallsyms address table\n");
		return 0;
	}
	fprintf(stderr, "[syms] kallsyms: %u symbols, _text=%#llx _end=%#llx\n",
		out->nb.count, (unsigned long long)out->text,
		(unsigned long long)out->end);
	return 1;
}

/* --------------------------------------------------------------- bootimg */

static int boot_kernel(const unsigned char *file, size_t flen,
		       const unsigned char **kern, size_t *klen)
{
	uint32_t kernel_size, header_version, page;
	uint64_t off;

	if (flen < 64 || memcmp(file, "ANDROID!", 8)) {
		*kern = file;
		*klen = flen;
		return 1;
	}
	kernel_size = rd32(file + 8);
	header_version = rd32(file + 40);
	if (header_version >= 3) {
		page = 4096;
	} else {
		page = rd32(file + 36);
		if (page < 512 || page > 65536 || (page & (page - 1))) {
			fprintf(stderr, "[syms] bad boot page size %u\n", page);
			return 0;
		}
	}
	off = page;
	if (!kernel_size || off + kernel_size > flen) {
		fprintf(stderr, "[syms] bad boot kernel range (size=%u)\n",
			kernel_size);
		return 0;
	}
	fprintf(stderr, "[syms] boot.img v%u: kernel at %#llx, %u bytes\n",
		header_version, (unsigned long long)off, kernel_size);
	*kern = file + off;
	*klen = kernel_size;
	return 1;
}

/* ---------------------------------------------------------- decompression */

struct outbuf {
	unsigned char *p;
	size_t len;
	size_t cap;
};

static int ob_need(struct outbuf *o, size_t add)
{
	if (o->len + add <= o->cap)
		return 1;
	{
		size_t cap = o->cap ? o->cap : (1u << 20);

		while (cap < o->len + add)
			cap *= 2;
		{
			unsigned char *n = realloc(o->p, cap);

			if (!n) {
				fprintf(stderr,
					"[syms] out of memory (decompress)\n");
				return 0;
			}
			o->p = n;
			o->cap = cap;
		}
	}
	return 1;
}

static int lz4_legacy_decode(const unsigned char *src, size_t n,
			     unsigned char **outp, size_t *outlen)
{
	static const unsigned char magic[4] = { 0x02, 0x21, 0x4c, 0x18 };
	struct outbuf o = { 0, 0, 0 };
	size_t i = 4;

	if (n < 4 || memcmp(src, magic, 4))
		return 0;
	while (i + 4 <= n) {
		uint32_t bsz = rd32(src + i);
		const unsigned char *blk;
		size_t p = 0;

		i += 4;
		if (!bsz)
			break;
		if (i + bsz > n)
			goto bad;
		blk = src + i;
		while (p < bsz) {
			unsigned token = blk[p++];
			size_t ll = token >> 4;
			size_t ml, start;

			if (ll == 15) {
				unsigned s;
				do {
					if (p >= bsz)
						goto bad;
					s = blk[p++];
					ll += s;
				} while (s == 255);
			}
			if (p + ll > bsz)
				goto bad;
			if (!ob_need(&o, ll))
				goto bad;
			memcpy(o.p + o.len, blk + p, ll);
			o.len += ll;
			p += ll;
			if (p >= bsz)
				break;
			if (p + 2 > bsz)
				goto bad;
			start = (size_t)blk[p] | ((size_t)blk[p + 1] << 8);
			p += 2;
			if (!start || start > o.len)
				goto bad;
			ml = (token & 15) + 4;
			if ((token & 15) == 15) {
				unsigned s;
				do {
					if (p >= bsz)
						goto bad;
					s = blk[p++];
					ml += s;
				} while (s == 255);
			}
			if (!ob_need(&o, ml))
				goto bad;
			start = o.len - start;
			{
				size_t k;

				for (k = 0; k < ml; k++)
					o.p[o.len + k] = o.p[start + k];
			}
			o.len += ml;
		}
		i += bsz;
	}
	if (!o.len)
		goto bad;
	*outp = o.p;
	*outlen = o.len;
	return 1;
bad:
	free(o.p);
	return -1;
}

static int gzip_decode(const unsigned char *src, size_t n,
		       unsigned char **outp, size_t *outlen)
{
#if defined(IC_SYMS_HAVE_ZLIB)
	z_stream z;
	struct outbuf o = { 0, 0, 0 };
	int rc;

	memset(&z, 0, sizeof(z));
	if (inflateInit2(&z, 15 + 32) != Z_OK)
		return -1;
	z.next_in = (Bytef *)src;
	z.avail_in = (uInt)n;
	for (;;) {
		if (!ob_need(&o, 1u << 20)) {
			inflateEnd(&z);
			free(o.p);
			return -1;
		}
		z.next_out = o.p + o.len;
		z.avail_out = (uInt)(o.cap - o.len);
		rc = inflate(&z, Z_NO_FLUSH);
		o.len = o.cap - z.avail_out;
		if (rc == Z_STREAM_END)
			break;
		if (rc != Z_OK) {
			inflateEnd(&z);
			free(o.p);
			return -1;
		}
	}
	inflateEnd(&z);
	*outp = o.p;
	*outlen = o.len;
	return 1;
#else
	(void)src;
	(void)n;
	(void)outp;
	(void)outlen;
	fprintf(stderr, "[syms] gzip kernel: this build has no zlib; use the "
			"PC parser (tool/parse_offsets.py)\n");
	return -2;
#endif
}

static int decompress_kernel(const unsigned char *kern, size_t klen,
			     unsigned char **outp, size_t *outlen)
{
	int rc;

	if (klen >= 4 && kern[0] == 0x02 && kern[1] == 0x21 &&
	    kern[2] == 0x4c && kern[3] == 0x18) {
		rc = lz4_legacy_decode(kern, klen, outp, outlen);
		if (rc <= 0) {
			fprintf(stderr, "[syms] lz4-legacy decompress failed\n");
			return 0;
		}
		fprintf(stderr, "[syms] lz4-legacy: %zu -> %zu bytes\n",
			klen, *outlen);
		return 1;
	}
	if (klen >= 2 && kern[0] == 0x1f && kern[1] == 0x8b) {
		rc = gzip_decode(kern, klen, outp, outlen);
		if (rc <= 0) {
			if (rc == -2)
				return 0;
			fprintf(stderr, "[syms] gzip decompress failed\n");
			return 0;
		}
		fprintf(stderr, "[syms] gzip: %zu -> %zu bytes\n", klen,
			*outlen);
		return 1;
	}
	if (klen >= 4 && kern[0] == 0x28 && kern[1] == 0xb5 &&
	    kern[2] == 0x2f && kern[3] == 0xfd) {
		fprintf(stderr, "[syms] zstd kernel is not supported on-device; "
				"use tool/parse_offsets.py\n");
		return 0;
	}
	*outp = NULL;
	*outlen = klen;
	return 1;
}

/* ------------------------------------------------------------------- ELF */

static int parse_elf(const unsigned char *img, size_t len,
		     struct ic_sym_entry *tab, int cap, int *n_out,
		     char *build, size_t buildlen, char *version,
		     size_t versionlen)
{
	uint64_t shoff;
	uint16_t shentsize, shnum;
	size_t i;
	int nsym = 0;

	if (len < 64 || img[0] != 0x7f || img[1] != 'E' || img[2] != 'L' ||
	    img[3] != 'F' || img[4] != 2 || img[5] != 1)
		return 0;
	shoff = rd64(img + 0x28);
	shentsize = rd16(img + 0x3a);
	shnum = rd16(img + 0x3c);
	if (shentsize < 64 || shoff + (uint64_t)shnum * shentsize > len)
		return 0;
	for (i = 0; i < shnum; i++) {
		const unsigned char *sh = img + shoff + i * shentsize;
		uint32_t type = rd32(sh + 4);
		uint32_t link = rd32(sh + 0x28);
		uint64_t off = rd64(sh + 0x18);
		uint64_t size = rd64(sh + 0x20);
		uint64_t entsize = rd64(sh + 0x38);
		uint64_t j;

		if (type != 2 || link >= shnum || !entsize || entsize < 24)
			continue;
		{
			const unsigned char *st = img + shoff + link * shentsize;
			uint64_t str_off = rd64(st + 0x18);
			uint64_t str_size = rd64(st + 0x20);

			if (str_off + str_size > len || off + size > len)
				continue;
			for (j = 0; j + 24 <= size; j += entsize) {
				const unsigned char *sym = img + off + j;
				uint32_t name_off = rd32(sym);
				uint64_t value = rd64(sym + 8);
				const char *name;
				int k;

				if (!value || name_off >= str_size)
					continue;
				name = (const char *)(img + str_off + name_off);
				if (!memchr(name, 0, str_size - name_off))
					continue;
				if (!ic_syms_is_required(name))
					continue;
				for (k = 0; k < nsym; k++)
					if (!strcmp(tab[k].name, name))
						break;
				if (k < nsym)
					continue;
				if (nsym < cap) {
					snprintf(tab[nsym].name,
						 sizeof(tab[nsym].name), "%s",
						 name);
					tab[nsym].addr = value;
					nsym++;
				}
			}
		}
	}
	if (!nsym)
		return 0;
	*n_out = nsym;
	ic_syms_banner_release(img, len, build, buildlen);
	if (versionlen)
		version[0] = 0;
	return 1;
}

/* ------------------------------------------------------------------ text */

static int hex_addr(const char *s, uint64_t *out)
{
	char *end;
	unsigned long long v;

	if (!s || !*s)
		return 0;
	while (*s == ' ' || *s == '\t')
		s++;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	if (!*s)
		return 0;
	v = strtoull(s, &end, 16);
	if (end == s)
		return 0;
	*out = (uint64_t)v;
	return 1;
}

static int parse_text(const unsigned char *img, size_t len,
		      struct ic_sym_entry *tab, int cap, int *n_out,
		      char *build, size_t buildlen, char *version,
		      size_t versionlen)
{
	char *buf = xmalloc(len + 1);
	size_t pos = 0;
	int nsym = 0;

	memcpy(buf, img, len);
	buf[len] = 0;
	build[0] = 0;
	version[0] = 0;
	while (pos < len) {
		char *line = buf + pos, *nl, *p, *eq, *tok[5];
		int ntok = 0;
		uint64_t addr = 0;
		char *name = NULL;
		int has_addr = 0;

		nl = memchr(line, '\n', len - pos);
		if (nl)
			*nl = 0;
		pos += nl ? (size_t)(nl - line) + 1 : len - pos;
		{
			size_t ll = strlen(line);

			while (ll && (line[ll - 1] == '\r' ||
				      line[ll - 1] == ' ' ||
				      line[ll - 1] == '\t'))
				line[--ll] = 0;
		}
		p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			continue;
		if (p[0] == '#') {
			p++;
			while (*p == ' ')
				p++;
			if (!strncmp(p, "build=", 6)) {
				snprintf(build, buildlen, "%s", p + 6);
			} else if (!strncmp(p, "version=", 8)) {
				snprintf(version, versionlen, "%s", p + 8);
			}
			continue;
		}
		eq = strchr(p, '=');
		if (eq) {
			char *a = p, *b = eq + 1;

			*eq = 0;
			while (*a == ' ' || *a == '\t')
				a++;
			while (*b == ' ' || *b == '\t')
				b++;
			if (!strncmp(a, "build", 5)) {
				snprintf(build, buildlen, "%s", b);
				continue;
			}
			if (!strncmp(a, "version", 7)) {
				snprintf(version, versionlen, "%s", b);
				continue;
			}
			if (hex_addr(b, &addr) && ic_syms_is_required(a))
				name = a;
			else if (hex_addr(a, &addr) && ic_syms_is_required(b))
				name = b;
			if (!name)
				continue;
			has_addr = 1;
		} else {
			char *q = p;

			while (*q && ntok < 5) {
				while (*q == ' ' || *q == '\t')
					q++;
				if (!*q)
					break;
				tok[ntok++] = q;
				while (*q && *q != ' ' && *q != '\t')
					q++;
				if (*q)
					*q++ = 0;
			}
			if (ntok < 2)
				continue;
			{
				int i;

				for (i = 0; i < ntok; i++)
					if (ic_syms_is_required(tok[i])) {
						name = tok[i];
						break;
					}
				if (!name)
					continue;
				for (i = 0; i < ntok; i++) {
					if (tok[i] == name)
						continue;
					if (hex_addr(tok[i], &addr)) {
						has_addr = 1;
						break;
					}
				}
			}
		}
		if (!name || !has_addr || !addr)
			continue;
		{
			int k;

			for (k = 0; k < nsym; k++)
				if (!strcmp(tab[k].name, name))
					break;
			if (k < nsym)
				continue;
			if (nsym >= cap)
				continue;
			snprintf(tab[nsym].name, sizeof(tab[nsym].name), "%s",
				 name);
			tab[nsym].addr = addr;
			nsym++;
		}
	}
	free(buf);
	if (!nsym)
		return 0;
	*n_out = nsym;
	return 1;
}

/* --------------------------------------------------------------- output */

static int write_table(const char *out_path, const struct ic_sym_entry *tab,
		       int n, const char *build, const char *version)
{
	FILE *f = stdout;
	int i;

	if (out_path && strcmp(out_path, "-")) {
		f = fopen(out_path, "w");
		if (!f) {
			fprintf(stderr, "[syms] cannot write %s: %s\n", out_path,
				strerror(errno));
			return 0;
		}
	}
	fprintf(f, "# ic-timer symbol table\n");
	if (build && *build)
		fprintf(f, "# build=%s\n", build);
	if (version && *version)
		fprintf(f, "# version=%s\n", version);
	for (i = 0; i < ic_syms_required_n; i++) {
		int k;

		for (k = 0; k < n; k++)
			if (!strcmp(tab[k].name, ic_syms_required[i])) {
				fprintf(f, "%s=0x%llx\n", tab[k].name,
					(unsigned long long)tab[k].addr);
				break;
			}
	}
	/* Optional symbols: emitted when the image has them, so a device
	 * using an external table still gets the panic_on_warn net and the
	 * module-load bypass addresses without a second parsing step. */
	{
		static const char *const opt[] = {
			"sig_enforce", "module_notify_list", "panic_on_warn",
		};
		unsigned int o;

		for (o = 0; o < sizeof(opt) / sizeof(opt[0]); o++) {
			int k;

			for (k = 0; k < n; k++)
				if (!strcmp(tab[k].name, opt[o])) {
					fprintf(f, "%s=0x%llx\n", tab[k].name,
						(unsigned long long)tab[k].addr);
					break;
				}
		}
	}
	if (f != stdout)
		fclose(f);
	return 1;
}

int ic_syms_load_file(const char *path, struct ic_sym_entry *tab, int cap,
		      char *build, size_t buildlen, char *version,
		      size_t versionlen)
{
	size_t len = 0, pos = 0;
	unsigned char *buf;
	int n = 0;

	buf = read_file(path, &len, 32u << 20);
	if (!buf)
		return -1;
	if (build && buildlen)
		build[0] = 0;
	if (version && versionlen)
		version[0] = 0;
	while (pos < len) {
		char *line = (char *)(buf + pos), *nl, *p;
		char *eq;
		uint64_t addr;

		nl = memchr(line, '\n', len - pos);
		if (nl)
			*nl = 0;
		pos += (nl ? (size_t)(nl - line) + 1 : len - pos);
		{
			size_t l = strlen(line);

			while (l && (line[l - 1] == '\r' ||
				     line[l - 1] == ' ' ||
				     line[l - 1] == '\t'))
				line[--l] = 0;
		}
		p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			continue;
		if (*p == '#') {
			p++;
			while (*p == ' ')
				p++;
			if (build && buildlen && !strncmp(p, "build=", 6)) {
				snprintf(build, buildlen, "%s", p + 6);
				continue;
			}
			if (version && versionlen &&
			    !strncmp(p, "version=", 8)) {
				snprintf(version, versionlen, "%s", p + 8);
				continue;
			}
			continue;
		}
		eq = strchr(p, '=');
		if (eq) {
			char *name = p, *val = eq + 1;

			*eq = 0;
			while (*name == ' ' || *name == '\t')
				name++;
			while (*val == ' ' || *val == '\t')
				val++;
			if (!ic_syms_is_required(name) || !hex_addr(val, &addr))
				continue;
			if (n < cap) {
				snprintf(tab[n].name, sizeof(tab[n].name), "%s",
					 name);
				tab[n].addr = addr;
				n++;
			}
		}
	}
	free(buf);
	return n;
}

int ic_syms_parse_file(const char *in_path, const char *out_path, int verbose)
{
	struct ic_sym_entry tab[IC_SYMS_MAX];
	size_t len = 0;
	unsigned char *file;
	const unsigned char *kern;
	size_t klen;
	unsigned char *dec = NULL;
	size_t declen = 0;
	const unsigned char *img;
	size_t img_len;
	char build[192] = "", version[320] = "";
	int n = 0, ok = 0;

	file = read_file(in_path, &len, 512u << 20);
	if (!file)
		return -1;
	if (verbose)
		fprintf(stderr, "[syms] input %s (%zu bytes)\n", in_path, len);

	if (len >= 4 && file[0] == 0x7f && file[1] == 'E' &&
	    file[2] == 'L' && file[3] == 'F') {
		if (verbose)
			fprintf(stderr, "[syms] ELF vmlinux path\n");
		if (!parse_elf(file, len, tab, IC_SYMS_MAX, &n, build,
			       sizeof(build), version, sizeof(version))) {
			fprintf(stderr, "[syms] ELF has no usable .symtab\n");
			goto out;
		}
		ok = 1;
		goto emit;
	}
	{
		size_t text_bytes = len < 4096 ? len : 4096, i, printable = 0;

		for (i = 0; i < text_bytes; i++)
			if (file[i] == '\n' || file[i] == '\r' ||
			    file[i] == '\t' ||
			    (file[i] >= 0x20 && file[i] < 0x7f))
				printable++;
		if (text_bytes && printable * 100 >= text_bytes * 95) {
			if (verbose)
				fprintf(stderr, "[syms] text symbol file path\n");
			if (!parse_text(file, len, tab, IC_SYMS_MAX, &n, build,
					sizeof(build), version, sizeof(version))) {
				fprintf(stderr,
					"[syms] no required symbols in text file\n");
				goto out;
			}
			ok = 1;
			goto emit;
		}
	}

	if (!boot_kernel(file, len, &kern, &klen))
		goto out;
	if (!decompress_kernel(kern, klen, &dec, &declen))
		goto out;
	img = dec ? dec : kern;
	img_len = dec ? declen : klen;
	ic_syms_banner_release(img, img_len, build, sizeof(build));
	if (!build[0])
		fprintf(stderr, "[syms] warning: no Linux version banner found\n");
	{
		struct recovered rec;
		uint32_t i;

		if (!recover_kallsyms(img, img_len, &rec))
			goto out;
		for (i = 0; i < rec.nb.count; i++) {
			const char *name = rec.nb.names + rec.nb.name_off[i];

			if (!ic_syms_is_required(name))
				continue;
			if (n >= IC_SYMS_MAX)
				break;
			snprintf(tab[n].name, sizeof(tab[n].name), "%s", name);
			tab[n].addr = rec.addrs[i];
			n++;
		}
		free_name_block(&rec.nb);
		free(rec.addrs);
	}
	ok = 1;

emit:
	if (ok) {
		int i, targets = 0;

		for (i = 0; i < n; i++) {
			int t;

			for (t = ic_syms_required_n - IC_SYMS_NTARGET;
			     t < ic_syms_required_n; t++)
				if (!strcmp(tab[i].name, ic_syms_required[t]))
					targets++;
		}
		if (targets != IC_SYMS_NTARGET) {
			fprintf(stderr,
				"[syms] incomplete: %d/%d targets, %d symbols\n",
				targets, IC_SYMS_NTARGET, n);
			ok = 0;
		} else if (n < 8) {
			fprintf(stderr, "[syms] only %d symbols; refusing\n", n);
			ok = 0;
		}
	}
	if (ok) {
		if (!write_table(out_path, tab, n, build, version))
			ok = 0;
		else
			fprintf(stderr, "[syms] wrote %d symbols to %s "
					"(build=%s)\n", n,
				(out_path && strcmp(out_path, "-")) ? out_path
								    : "stdout",
				build[0] ? build : "?");
	}
out:
	free(dec);
	free(file);
	return ok ? 0 : -1;
}
