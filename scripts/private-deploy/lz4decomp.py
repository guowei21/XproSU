#!/usr/bin/env python3
"""LZ4 legacy frame (magic 0x184C2102 + [u32 cSize][block]*) -> raw arm64 Image"""
import struct, sys

def lz4_block(src, i, n, out):
    """decode one LZ4 block starting at i, appending to out; return new i"""
    while i < n:
        token = src[i]; i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]; i += 1; lit += b
                if b != 255: break
        if lit:
            out += src[i:i+lit]; i += lit
        if i >= n: break
        off = src[i] | (src[i+1] << 8); i += 2
        if off == 0 or off > len(out):
            raise ValueError("bad offset %#x at out %#x" % (off, len(out)))
        ml = (token & 0xF)
        if ml == 15:
            while True:
                b = src[i]; i += 1; ml += b
                if b != 255: break
        ml += 4
        s = len(out) - off
        out += out[s:s+ml]
    return i

def lz4_legacy(data, verbose=True):
    if data[:4] != b"\x02\x21\x4c\x18":
        raise ValueError("magic mismatch: %s" % data[:4].hex())
    out = bytearray(); i = 4; n = len(data); blk = 0
    while i + 4 <= n:
        csize = struct.unpack_from("<I", data, i)[0]; i += 4
        if csize == 0 or i + csize > n:
            if verbose: print("  block %d: csize=0x%x -> stop at 0x%x" % (blk, csize, i))
            break
        before = len(out)
        i = lz4_block(data, i, i + csize, out)
        blk += 1
        if verbose:
            print("  block %d: csize=0x%x out=0x%x" % (blk, csize, len(out) - before))
        if i + 4 > n: break
    return bytes(out)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: %s <kernel.payload(lz4 legacy)> [out_Image]" % sys.argv[0])
    SRC = sys.argv[1]
    DST = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(SRC)), "Image")
    d = open(SRC, "rb").read()
    o = lz4_legacy(d)
    print("compressed=0x%x decompressed=0x%x" % (len(d), len(o)))
    open(DST, "wb").write(o)
    print("written ->", DST)
    if o[56:60] == b"ARM\x64" or True:
        i = o.find(b"ARM\x64")
        print("ARMd at", hex(i))
        if i >= 56:
            s = i - 56
            co0, co1 = struct.unpack_from("<II", o, s)
            toff = struct.unpack_from("<Q", o, s+8)[0]
            isz, fl = struct.unpack_from("<QQ", o, s+16)
            print("  Image @0x%x code0=0x%08x code1=0x%08x text_offset=0x%x image_size=0x%x flags=0x%x"
                  % (s, co0, co1, toff, isz, fl))
    for pat in (b"Linux version", b"6.1.57", b"\x9f\xeb\x01\x00"):
        p = o.find(pat)
        print("%-16s -> %s" % (pat.decode('latin1'), hex(p) if p >= 0 else "none"))
