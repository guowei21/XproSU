package com.ghostlock.pro.domain.model

/**
 * Kernel releases this build carries offsets for.
 *
 * Hand-written on purpose.  The build used to derive this list, plus a full
 * release -> field -> value map, from `src/kernels/<release>/offsets.h`; the generated
 * map put every struct field name into the dex as a string literal, and the
 * tables themselves sat in `.rodata` as plaintext.  Both are gone: offsets now
 * live in an opaque container the app never parses
 * (`docs/offsets-binary-format.md`), so only release strings -- public kernel
 * identifiers -- remain here.
 *
 * Keep in step with the releases packed into `app/src/main/assets/offsets.glt`.
 */
object SupportedKernels {
    val UNAMES: Set<String> = setOf(
        "6.1.124-android14-11-maybe-dirty",
        "6.1.145-android14-11-maybe-dirty",
        "6.1.57-android14-11-maybe-dirty",
    )
}
