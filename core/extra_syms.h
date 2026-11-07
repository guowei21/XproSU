#ifndef IC_EXTRA_SYMS_H
#define IC_EXTRA_SYMS_H

/*
 * Per-build fake-cred objects that the old 66-entry anchor tables never
 * carried.  They are data symbols (not code anchors), so they cannot be
 * derived from a table; they are extracted from the image of each build we
 * have locally, which makes those builds work from the built-in table alone
 * (no external ic-syms.txt, i.e. the same result as "解析偏移").
 *
 * Keyed by the anchor table's name.  Missing builds simply fall back to the
 * external table.
 */
struct ic_extra_syms {
    const char *table;
    unsigned long long root_user;
    unsigned long long init_ucounts;
    unsigned long long init_groups;
};

static const struct ic_extra_syms ic_extra_syms_tab[] = {
    /* 6.1.145-android14-11-maybe-dirty, iQOO 12 16.2.11 (download_kernel.Image) */
    { "iqoo12-16.2.11", 0xffffffc00a121108ULL, 0xffffffc00a1229b8ULL,
      0xffffffc00a122428ULL },
    /* 6.1.145-android14-11-maybe-dirty, PD2307/PD2329 16.2.21.1
     * (iqoo12-16211-kernel.Image; tp=0xffffffc00a3cc1c0 matches the table) */
    { "ic_iqoo12_16211_links", 0xffffffc00a1f11c8ULL, 0xffffffc00a1f2a78ULL,
      0xffffffc00a1f24e8ULL },
    /* PD2307 16.2.20.3 / 16.2.20.7 share ic_iqoo12_links; extracted from
     * pd2307-162207-boot.img (tp=0xffffffc00a3cb180 and
     * selinux=0xffffffc00a558f40 both match the table). */
    { "ic_iqoo12_links", 0xffffffc00a1f11c8ULL, 0xffffffc00a1f2a78ULL,
      0xffffffc00a1f24e8ULL },
    /* PD2516/V2516 (Y500 Pro) 16.1.11.0, kernel_y500pro_16110.img
     * (tp=0xffffffc00a2d17e0 / selinux=0xffffffc00a45d8c8 match). */
    { "ic_y500pro_16110_links", 0xffffffc00a101088ULL, 0xffffffc00a102938ULL,
      0xffffffc00a1023a8ULL },
    /* PD2324 (X100 series) 16.2.12.0, pd2324_kernel.Image
     * (tp=0xffffffc00a2f3600 matches). */
    { "ic_pd2324_links", 0xffffffc00a121108ULL, 0xffffffc00a1229b8ULL,
      0xffffffc00a122428ULL },
};

#endif /* IC_EXTRA_SYMS_H */
