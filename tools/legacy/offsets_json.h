#ifndef OFFSETS_JSON_H
#define OFFSETS_JSON_H

#include <stddef.h>
#include "../../src/kernels/offsets.h"

/* Fill `out` from the JSON entry whose "release" equals `release`, in the
 * format tools/extract_rs/ghostlock-extract --format json writes. Missing
 * fields keep their values; returns 0 on match, -1 otherwise. release_buf
 * gets a copy of the matched release string. */
int load_offsets_json(const char *path, const char *release,
                      struct kernel_offsets *out, char *release_buf,
                      size_t release_buf_cap);


/* The plaintext importer's own gate function.  The engine no longer links
 * this file -- the runtime gate set now lives in src/core/offsets_bin.c and
 * reports numeric field ids instead of names, because the names were
 * themselves a leak.  This copy is kept so tools/glt_equiv_test.c can still
 * prove that the .glt container decodes to exactly what the JSON path did;
 * it is never compiled into libghostlock.so. */
int gl_validate_offsets_entry(const struct kernel_offsets *o,
                              const char *release);
#endif
