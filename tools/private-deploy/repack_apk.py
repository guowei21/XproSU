#!/usr/bin/env python3
"""Repack the base APK with a new libghostlock.so.
- drops META-INF/* (re-signed later)
- keeps each entry's original compression method
- aligns STORED entries: .so -> 16384, resources.arsc -> 4096, others -> 4
"""
import sys, zipfile, struct, binascii, zlib

src_apk, dst_apk, new_so_path = sys.argv[1], sys.argv[2], sys.argv[3]
TARGET_SO = "lib/arm64-v8a/libghostlock.so"
new_so = open(new_so_path, "rb").read()

zin = zipfile.ZipFile(src_apk)
entries = []
for it in zin.infolist():
    if it.filename.startswith("META-INF/"):
        continue
    data = new_so if it.filename == TARGET_SO else zin.read(it.filename)
    entries.append((it, data))

def align_for(name, method):
    if method != zipfile.ZIP_STORED:
        return 1
    if name.endswith(".so"):
        return 16384
    if name.endswith("resources.arsc"):
        return 4096
    return 4

out = open(dst_apk, "wb")
central = []
offset = 0

for it, data in entries:
    name = it.filename.encode("utf-8")
    method = it.compress_type
    dt = it.date_time
    dostime = (dt[3] << 11) | (dt[4] << 5) | (dt[5] // 2)
    dosdate = ((dt[0] - 1980) << 9) | (dt[1] << 5) | dt[2]
    crc = binascii.crc32(data) & 0xffffffff

    if method == zipfile.ZIP_STORED:
        comp = data
        align = align_for(it.filename, method)
        need = offset + 30 + len(name)
        pad = (-need) % align
        extra = b"\x00" * pad
        csize = usize = len(data)
    else:
        co = zlib.compressobj(9, zlib.DEFLATED, -15)
        comp = co.compress(data) + co.flush()
        extra = b""
        csize = len(comp)
        usize = len(data)

    lho = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, method, dostime, dosdate,
                      crc, csize, usize, len(name), len(extra))
    out.write(lho + name + extra + comp)
    central.append((it, name, crc, csize, usize, method, offset, dostime, dosdate))
    offset = out.tell()

cd_start = offset
for it, name, crc, csize, usize, method, lho_off, dostime, dosdate in central:
    ch = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 0x0314, 20, 0, method,
                     dostime, dosdate, crc, csize, usize, len(name), 0, 0, 0, 0,
                     it.external_attr, lho_off)
    out.write(ch + name)
cd_size = out.tell() - cd_start
out.write(struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(central), len(central),
                      cd_size, cd_start, 0))
out.close()

z = zipfile.ZipFile(dst_apk)
assert z.testzip() is None
f = open(dst_apk, "rb")
for n in (TARGET_SO, "resources.arsc"):
    try:
        i = z.getinfo(n)
    except KeyError:
        continue
    f.seek(i.header_offset)
    hdr = f.read(30)
    _, _, _, m, _, _, _, _, _, nl, el = struct.unpack("<IHHHHHIIIHH", hdr)
    off = i.header_offset + 30 + nl + el
    print(f"  {n}: method={m} data_off={off} mod16384={off % 16384} mod4096={off % 4096} size={i.file_size}")
import os
print("wrote", dst_apk, os.path.getsize(dst_apk), "bytes, entries", len(central))
