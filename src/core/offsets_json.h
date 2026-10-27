#ifndef OFFSETS_JSON_H
#define OFFSETS_JSON_H

#include <stddef.h>
#include "../kernels/offsets.h"

/* Fill `out` from the JSON entry whose "release" equals `release`, in the
 * format tools/extract_rs/ghostlock-extract --format json writes.  Missing
 * fields keep their values; release_buf gets a copy of the matched release.
 *
 * `build` is this kernel's `uname -v`.  An entry carrying a non-empty "build"
 * is only accepted when it matches, so two devices that share a release string
 * but run different vmlinux images cannot take each other's table.
 *
 * Returns 0 on match, -1 when nothing matched, -2 when the release matched but
 * the build tag disagreed. */
int load_offsets_json(const char *path, const char *release, const char *build,
                      struct kernel_offsets *out, char *release_buf,
                      size_t release_buf_cap);

#endif
