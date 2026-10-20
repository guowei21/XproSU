#!/usr/bin/env python3
import struct, sys, os

BOOT = sys.argv[1] if len(sys.argv) > 1 else None
if not BOOT or not os.path.exists(BOOT):
    sys.exit("usage: %s <boot.img> [outdir=当前目录]" % sys.argv[0])
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()
os.makedirs(OUTDIR, exist_ok=True)
data = open(BOOT, "rb").read()
print("boot.img size:", len(data))

assert data[:8] == b"ANDROID!", "not an android boot image"
magic = data[:8]

def hdr_v0(d):
    (ks, ka, rs, ra, ss, sa, ta, ps, hv, osv) = struct.unpack_from("<10I", d, 8)
    return dict(kernel_size=ks, kernel_addr=ka, ramdisk_size=rs, ramdisk_addr=ra,
                second_size=ss, second_addr=sa, tags_addr=ta, page_size=ps,
                header_version=hv, os_version=hex(osv))

def hdr_v3(d):
    (ks, rs, osv, hsz, r0, r1, r2, r3, hv) = struct.unpack_from("<9I", d, 8)
    return dict(kernel_size=ks, ramdisk_size=rs, os_version=hex(osv), header_size=hsz,
                reserved=(r0, r1, r2, r3), header_version=hv)

def hdr_v4(d):
    (ks, rs, osv, hsz, r0, r1, r2, r3, hv, sigsz) = struct.unpack_from("<10I", d, 8)
    return dict(kernel_size=ks, ramdisk_size=rs, os_version=hex(osv), header_size=hsz,
                reserved=(r0, r1, r2, r3), header_version=hv, signature_size=sigsz)

info = hdr_v0(data)
print("v0 view:", info)
if info["header_version"] in (3, 4):
    info = hdr_v4(data) if info["header_version"] == 4 else hdr_v3(data)
    print("v%d view: %s" % (info["header_version"], info))

# boot images use 4096-byte pages for v3/v4
page = 4096
ks = info["kernel_size"]; rs = info["ramdisk_size"]
print("kernel_size =", ks, "(%d pages)" % ((ks + page - 1)//page))
print("ramdisk_size =", rs)
kern = data[page:page+ks]
print("kernel first 64 bytes:", kern[:64].hex())

# format detection
def detect(b):
    if b[:4] == b"\x1f\x8b\x08": return "gzip"
    if b[:6] == b"\xfd7zXZ\x00": return "xz"
    if b[:4] == b"\x04\x22\x4d\x18": return "lz4"
    if b[:4] == b"\x28\xb5\x2f\xfd": return "zstd"
    if b[:3] == b"BZh": return "bzip2"
    return "raw"

fmt = detect(kern)
print("kernel format:", fmt)

# arm64 Image header: magic "ARM\x64" at 56, text_offset at 8
if kern[56:60] == b"ARM\x64":
    img_size, flags = struct.unpack_from("<QQ", kern, 16)
    text_offset = struct.unpack_from("<Q", kern, 8)[0]
    print("ARM64 Image: text_offset=0x%x image_size=0x%x flags=0x%x" % (text_offset, img_size, flags))

out = os.path.join(OUTDIR, "kernel.extracted")
if fmt == "raw":
    open(out, "wb").write(kern)
    print("written raw ->", out)
else:
    open(os.path.join(OUTDIR, "kernel.payload"), "wb").write(kern)
    print("compressed payload saved (decompress: scripts/lz4decomp.py <payload> <out>)")

# version string search in the raw kernel payload
for pat in (b"6.1.57", b"-android14-11-maybe-dirty", b"Linux version"):
    i = kern.find(pat)
    print("search %-28s -> %s" % (pat.decode(), hex(i) if i >= 0 else "not found"))
    if i >= 0:
        s = kern[max(0,i-80):i+120]
        print("   ctx:", s.replace(b"\x00", b".")[:200])
