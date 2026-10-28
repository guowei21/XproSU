#!/usr/bin/env python3
"""Recover the embedded kallsyms table from an uncompressed arm64 Image.

Port of tools/extract_rs/src/kallsyms_finder.rs (same invariants):
token table -> markers -> num_syms/names -> offsets + relative_base.

Usage: python tools/kallsyms_from_image.py <arm64 Image> [out.txt]

Output lines: "<hex address> <type> <name>", sorted by address (like /proc/kallsyms).
"""
import struct
import sys

ALIGN = 8
TOKEN_COUNT = 256
MAX_TOKEN_LEN = 256
MARKER_SEARCH_WINDOW = 4 * 1024 * 1024
NAME_TAIL_SEARCH = 0x40000
MIN_MARKERS = 8
MAX_MARKERS = 4096
SYMBOL_TYPES = set(b"aAbBcCdDeEfFgGiInNpPrRsStTuUvVwW?-")
REQUIRED = ("_text", "_end", "load_module")


def align_up(v, a=ALIGN):
    return (v + a - 1) & ~(a - 1)


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0] if o + 2 <= len(d) else None


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0] if o + 4 <= len(d) else None


def i32(d, o):
    return struct.unpack_from("<i", d, o)[0] if o + 4 <= len(d) else None


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0] if o + 8 <= len(d) else None


def arm64_image_size(d):
    if len(d) >= 64 and d[0x38:0x3c] == b"ARMd":
        size = u64(d, 0x10)
        if size:
            return size
    return len(d)


def find_subslice(d, needle, start=0):
    i = d.find(needle, start)
    return i if i >= 0 else None


def parse_token_table_at(d, start, digit_offset):
    if start % ALIGN:
        return None
    position = start
    token_starts = []
    token_offsets = []
    tokens = []
    for _ in range(TOKEN_COUNT):
        token_starts.append(position)
        end = d.find(b"\0", position, position + MAX_TOKEN_LEN + 1)
        if end < 0 or end == position:
            return None
        token = d[position:end]
        if any(b < 0x20 or b > 0x7e for b in token):
            return None
        token_offsets.append(position - start)
        tokens.append(token)
        position = end + 1
    if token_starts[0x30] != digit_offset:
        return None
    for value in b"0123456789_abcdefghijklmnopqrstuvwxyzT":
        if tokens[value] != bytes([value]):
            return None
    index_offset = align_up(position)
    if any(b != 0 for b in d[position:index_offset]):
        return None
    for idx, expected in enumerate(token_offsets):
        off = index_offset + idx * 2
        if off + 2 > len(d) or u16(d, off) != expected:
            return None
    return tokens, start, index_offset


def find_token_tables(d):
    needle = b"".join(bytes([v, 0]) for v in range(ord("0"), ord("9") + 1))
    tables = []
    pos = 0
    while True:
        digit_offset = find_subslice(d, needle, pos)
        if digit_offset is None:
            break
        earliest = max(0, digit_offset - 0x30 * (MAX_TOKEN_LEN + 1))
        start = align_up(earliest)
        while start <= digit_offset:
            got = parse_token_table_at(d, start, digit_offset)
            if got:
                tables.append(got)
            start += ALIGN
        pos = digit_offset + 1
    return tables


def read_markers(d, start, limit):
    if start % ALIGN or start + 8 > limit:
        return []
    first, second = u32(d, start), u32(d, start + 4)
    if first != 0 or not (0x200 <= (second or 0) <= 0x40000):
        return []
    markers = [first, second]
    position = start + 8
    while len(markers) < MAX_MARKERS and position + 4 <= limit:
        value = u32(d, position)
        if value is None:
            break
        delta = value - markers[-1]
        if not (0x200 <= delta <= 0x40000):
            break
        markers.append(value)
        position += 4
    return markers if len(markers) >= MIN_MARKERS else []


def parse_name_spans(d, names_offset, count, markers_offset, markers, uleb128):
    if count == 0 or len(markers) != (count + 255) // 256:
        return None
    spans = []
    position = names_offset
    for index in range(count):
        if index % 256 == 0 and position - names_offset != markers[index // 256]:
            return None
        if position >= markers_offset:
            return None
        length = d[position]
        position += 1
        if uleb128 and length & 0x80:
            if position >= markers_offset:
                return None
            high = d[position]
            if high & 0x80:
                return None
            length = (length & 0x7f) | (high << 7)
            position += 1
        if length == 0 or length > 0x3fff or position + length > markers_offset:
            return None
        spans.append((position, length))
        position += length
    if align_up(position) != markers_offset:
        return None
    if any(b != 0 for b in d[position:markers_offset]):
        return None
    return spans


def decode_names(d, spans, tokens):
    decoded = []
    for position, length in spans:
        encoded = d[position:position + length]
        expanded = b"".join(tokens[b] for b in encoded)
        if not expanded or len(expanded) > 4096:
            return None
        kind = expanded[0]
        name_bytes = expanded[1:]
        if not name_bytes or kind not in SYMBOL_TYPES:
            return None
        if any(b < 0x21 or b > 0x7e for b in name_bytes):
            return None
        decoded.append((kind, name_bytes.decode("latin1")))
    names = {name for _, name in decoded}
    if any(r not in names for r in REQUIRED):
        return None
    return decoded


def find_name_tables(d, tokens, token_table_offset):
    lower = max(0, token_table_offset - MARKER_SEARCH_WINDOW)
    marker_candidates = []
    position = align_up(lower)
    while position + 8 <= token_table_offset:
        markers = read_markers(d, position, token_table_offset)
        if markers:
            marker_candidates.append((position, markers))
        position += ALIGN

    recovered = []
    for markers_offset, markers in marker_candidates:
        min_count = (len(markers) - 1) * 256 + 1
        max_count = len(markers) * 256
        approximate_names = markers_offset - markers[-1]
        search_start = max(0, approximate_names - NAME_TAIL_SEARCH)
        num_off = approximate_names - (approximate_names % ALIGN)
        while num_off >= search_start + ALIGN:
            count = u32(d, num_off) or 0
            padding_ok = d[num_off + 4:num_off + 8] == b"\0\0\0\0"
            if min_count <= count <= max_count and padding_ok:
                names_offset = num_off + ALIGN
                seen = []
                for uleb in (True, False):
                    spans = parse_name_spans(d, names_offset, count, markers_offset, markers, uleb)
                    if spans is None or spans in seen:
                        continue
                    seen.append(spans)
                    decoded = decode_names(d, spans, tokens)
                    if decoded:
                        recovered.append((num_off, names_offset, markers_offset, decoded))
            if num_off < search_start + ALIGN:
                break
            num_off -= ALIGN
    return recovered


def is_arm64_kernel_address(address):
    return (address >> 48) == 0xFFFF and address % 4096 == 0


def decode_addresses(d, image_size, names, offsets_offset, relative_base_offset):
    count = len(names)
    offsets_end = offsets_offset + count * 4
    if offsets_end > len(d) or relative_base_offset < offsets_end:
        return None
    if relative_base_offset + 8 > len(d):
        return None
    if any(b != 0 for b in d[offsets_end:relative_base_offset]):
        return None
    relative_base = u64(d, relative_base_offset)
    if relative_base is None or not is_arm64_kernel_address(relative_base):
        return None
    signed = [i32(d, offsets_offset + i * 4) for i in range(count)]
    if any(v is None for v in signed):
        return None
    negative_count = sum(1 for v in signed if v < 0)
    if negative_count * 2 >= count:
        addresses = []
        for off in signed:
            value = relative_base - 1 - off if off < 0 else off
            if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
                return None
            addresses.append(value)
    else:
        addresses = [relative_base + (off & 0xFFFFFFFF) for off in signed]
    if any(addresses[i] > addresses[i + 1] for i in range(count - 1)):
        return None
    text = [a for a, (_, n) in zip(addresses, names) if n == "_text"]
    end = [a for a, (_, n) in zip(addresses, names) if n == "_end"]
    if len(text) != 1 or len(end) != 1 or text[0] != relative_base:
        return None
    if end[0] - text[0] != image_size:
        return None
    ordinary = [(a, k) for a, (k, _) in zip(addresses, names) if not (k in (ord("A"), ord("a"))) and a != 0]
    if not ordinary:
        return None
    inside = sum(1 for a, _ in ordinary if text[0] <= a <= end[0])
    if inside * 100 < len(ordinary) * 90:
        return None
    return [(a, k, n) for a, (k, n) in zip(addresses, names)]


def recover(d):
    image_size = arm64_image_size(d)
    token_tables = find_token_tables(d)
    print(f"# token tables: {len(token_tables)}", file=sys.stderr)
    candidates = []
    for tokens, table_offset, index_offset in token_tables:
        for num_off, names_off, markers_off, names in find_name_tables(d, tokens, table_offset):
            count = len(names)
            old_relative_base = num_off - ALIGN
            old_offsets = old_relative_base - align_up(count * 4)
            new_offsets = align_up(index_offset + TOKEN_COUNT * 2)
            new_relative_base = align_up(new_offsets + count * 4)
            for layout, offs, base in (
                ("pre-6.4", old_offsets, old_relative_base),
                ("6.4+", new_offsets, new_relative_base),
            ):
                entries = decode_addresses(d, image_size, names, offs, base)
                if entries:
                    print(f"# candidate {layout}: {len(entries)} symbols", file=sys.stderr)
                    candidates.append((layout, entries))
    if not candidates:
        raise SystemExit("no kallsyms table recovered")
    # Prefer a single candidate; if several, require identical symbol counts and pick the first.
    candidates.sort(key=lambda c: -len(c[1]))
    layout, entries = candidates[0]
    print(f"# selected {layout}, {len(entries)} symbols, image_size={image_size:#x}", file=sys.stderr)
    return entries


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    data = open(sys.argv[1], "rb").read()
    entries = recover(data)
    lines = [f"{address:016x} {chr(kind)} {name}" for address, kind, name in entries]
    text = "\n".join(lines) + "\n"
    if len(sys.argv) > 2:
        open(sys.argv[2], "w", encoding="utf-8", newline="\n").write(text)
        print(f"# wrote {sys.argv[2]}", file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
