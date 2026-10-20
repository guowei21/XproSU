"""Binary wire protocol for the XproSU App <-> license server (GlBlob.kt).

Little-endian throughout.  ``decode`` returns ``(kind, entries)``: ``kind`` is
1 for a request and 2 for a response, ``entries`` maps each u16 tag to its raw
byte value.  The u16 ``code`` field is deliberately not exposed by ``decode``;
request code is always zero and the server reconstructs response code from its
own business logic when encoding.
"""

from __future__ import annotations

import struct

MAGIC_WIRE = 0x9E4B37A1
VERSION = 1
KIND_REQUEST = 1
KIND_RESPONSE = 2
HEADER_SIZE = 12

# Request tags.
TAG_CARD = 0x21
TAG_DEVICE_FP = 0x22
TAG_PUBKEY = 0x23
TAG_APP_VER = 0x24
TAG_LOG = 0x25
TAG_TOKEN = 0x35

# Response tags.
TAG_TOKEN_RESP = 0x31
TAG_EXPIRE = 0x32
TAG_BLOB = 0x33
TAG_WRAPPED = 0x34
TAG_STATE = 0x36
TAG_MSG = 0x41


def encode(kind: int, code: int, entries: list[tuple[int, bytes]]) -> bytes:
    """Serialize a wire message: 12-byte header followed by count TLV entries."""
    if kind not in (KIND_REQUEST, KIND_RESPONSE):
        raise ValueError("kind must be 1 (request) or 2 (response)")
    if not 0 <= code <= 0xFFFF:
        raise ValueError("code out of u16 range")
    if not isinstance(entries, (list, tuple)):
        raise TypeError("entries must be a list of (tag, value) pairs")

    out = bytearray(struct.pack("<IBBHHH", MAGIC_WIRE, VERSION, kind, code, len(entries), 0))
    for tag, value in entries:
        if not 0 <= tag <= 0xFFFF:
            raise ValueError("tag out of u16 range")
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("entry value must be bytes")
        if len(value) > 0xFFFF:
            raise ValueError("entry value too long")
        out += struct.pack("<HH", tag, len(value))
        out += value
    return bytes(out)


def decode(data: bytes) -> tuple[int, dict[int, bytes]] | None:
    """Parse a wire message, or return None on any structural mismatch."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < HEADER_SIZE:
        return None
    magic, version, kind, _code, count, _reserved = struct.unpack_from("<IBBHHH", data, 0)
    if magic != MAGIC_WIRE or version != VERSION:
        return None

    pos = HEADER_SIZE
    entries: dict[int, bytes] = {}
    for _ in range(count):
        if pos + 4 > len(data):
            return None
        tag, length = struct.unpack_from("<HH", data, pos)
        pos += 4
        if pos + length > len(data):
            return None
        entries[tag] = bytes(data[pos : pos + length])
        pos += length

    if pos != len(data):
        return None
    return kind, entries


if __name__ == "__main__":
    entries = [
        (TAG_CARD, b"AAAAA-BBBBB-CCCCC-DDDDD"),
        (TAG_DEVICE_FP, b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        (TAG_APP_VER, b"1.1"),
    ]
    blob = encode(KIND_REQUEST, 0, entries)
    decoded = decode(blob)
    assert decoded == (KIND_REQUEST, {tag: value for tag, value in entries}), "wire round-trip failed"

    bad_magic = bytearray(blob)
    bad_magic[0] ^= 0x01
    assert decode(bytes(bad_magic)) is None, "wire bad magic accepted"

    trailing = blob + b"\x00"
    assert decode(trailing) is None, "wire trailing byte accepted"

    print("wire.py self-check OK")
