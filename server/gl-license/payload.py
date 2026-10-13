"""GLP payload and GLT2 container reader/writer (docs/stage2-protocol.md sec 4-5).

All integers are little-endian.  The GLP file holds the plaintext offset table;
GLT2 is that same payload encrypted per device with ChaCha20-Poly1305.
"""

from __future__ import annotations

import os
import struct

from crypto import (
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    fnv1a32,
    sha256,
)

GLP_MAGIC = b"GLP1"
GLP_VERSION = 1
GLT2_MAGIC = b"GLT2"
GLT2_VERSION = 2
GLT2_FLAG_AEAD = 0x02
GLT2_HDR_SIZE = 64

# field id <-> name, frozen by docs/stage2-protocol.md section 4.1
FIELD_IDS: dict[str, int] = {
    "kernel_phys_load": 0x11,
    "pselect_waiter_shift": 0x12,
    "off_init_task": 0x21,
    "off_init_cred": 0x22,
    "off_root_task_group": 0x23,
    "off_selinux_enforcing": 0x24,
    "off_selinux_blob_sizes": 0x25,
    "off_security_hook_heads": 0x26,
    "off_slide_nfulnl_logger": 0x27,
    "off_slide_loggers_0_1": 0x28,
    "off_slide_boot_id": 0x29,
    "off_tp_sys_exit_tp": 0x31,
    "off_tp_sys_exit_funcs": 0x32,
    "task_prio": 0x41,
    "task_normal_prio": 0x42,
    "task_sched_task_group": 0x43,
    "task_pi_lock": 0x44,
    "task_pi_waiters": 0x45,
    "task_pi_top_task": 0x46,
    "task_pi_blocked_on": 0x47,
    "task_pid": 0x48,
    "task_tgid": 0x49,
    "task_atomic_flags": 0x4A,
    "task_real_cred": 0x4B,
    "task_cred": 0x4C,
    "task_comm": 0x4D,
    "task_tasks": 0x4E,
    "task_seccomp": 0x4F,
    "compact_waiter": 0x51,
    "mm_struct_sz": 0x52,
}


def _resolve_field_id(key) -> int:
    if isinstance(key, int):
        fid = key
    elif isinstance(key, str):
        if key not in FIELD_IDS:
            raise KeyError(f"unknown GLP field name: {key}")
        fid = FIELD_IDS[key]
    else:
        raise TypeError("field key must be str or int")
    if not 0 <= fid <= 0xFFFF:
        raise ValueError(f"field id out of range: {fid}")
    return fid


def _serialize_glp(entries: dict) -> bytes:
    """Serialize a {release: {field_name_or_id: value}} table to GLP bytes.

    A release key may be the release string or an already-computed FNV-1a-32
    hash.  The hash form matters because the container does not carry the
    release name, so ``load_payload()`` can only hand back hashes; accepting
    them here keeps the load -> build round trip usable.

    Entries are emitted in ascending release-hash order and fields in ascending
    id order, so the output depends only on the table's content -- a build from
    release names and a rebuild from ``load_payload()``'s hashes are
    byte-identical, which is what makes the round trip checkable.
    """
    if not isinstance(entries, dict):
        raise TypeError("entries must be a dict keyed by release string or hash")
    out = bytearray()
    out += GLP_MAGIC
    out += bytes([GLP_VERSION, 0])
    out += struct.pack("<H", len(entries))

    blocks = []
    for release, fields in entries.items():
        if not isinstance(fields, dict):
            raise TypeError(f"fields for release {release!r} must be a dict")
        if isinstance(release, int):
            if not 0 <= release <= 0xFFFFFFFF:
                raise ValueError(f"release hash out of u32 range: {release}")
            release_hash = release
        else:
            release_hash = fnv1a32(release)
        blocks.append((release_hash, fields))
    blocks.sort(key=lambda pair: pair[0])

    for release_hash, fields in blocks:
        resolved = []
        for key, value in fields.items():
            fid = _resolve_field_id(key)
            if isinstance(value, bool) or not isinstance(value, int):
                try:
                    value = int(value, 0)
                except (TypeError, ValueError):
                    raise ValueError(f"field {key!r} value must be an integer") from None
            if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"field {key!r} value out of u64 range: {value}")
            resolved.append((fid, value))
        resolved.sort(key=lambda pair: pair[0])

        out += struct.pack("<IHH", release_hash, len(resolved), 0)
        for fid, value in resolved:
            out += struct.pack("<HQ", fid, value)
    return bytes(out)


def build_payload(entries: dict, path: str) -> bytes:
    """Build payload.bin from a plaintext table and write it to ``path``."""
    data = _serialize_glp(entries)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return data


def load_payload(path: str) -> dict:
    """Read payload.bin, returning {release_hash: {field_id: value}}."""
    with open(path, "rb") as fh:
        data = fh.read()
    return _deserialize_glp(data)


def _deserialize_glp(data: bytes) -> dict:
    if len(data) < 8 or data[:4] != GLP_MAGIC:
        raise ValueError("not a GLP file")
    version = data[4]
    if version != GLP_VERSION:
        raise ValueError(f"unsupported GLP version {version}")
    entry_count = struct.unpack_from("<H", data, 6)[0]
    pos = 8
    result: dict[int, dict[int, int]] = {}
    for _ in range(entry_count):
        if pos + 8 > len(data):
            raise ValueError("truncated GLP entry header")
        release_hash, field_count, _reserved = struct.unpack_from("<IHH", data, pos)
        pos += 8
        fields: dict[int, int] = {}
        for _ in range(field_count):
            if pos + 10 > len(data):
                raise ValueError("truncated GLP field")
            fid, value = struct.unpack_from("<HQ", data, pos)
            pos += 10
            fields[fid] = value
        result[release_hash] = fields
    if pos != len(data):
        raise ValueError(f"GLP trailing bytes: {len(data) - pos}")
    return result


def build_glt2(
    payload_entries: dict,
    release: str,
    device_fp: bytes,
    card_key: str | bytes,
    kd: bytes,
    expire: int,
    nonce: bytes | None = None,
) -> bytes:
    """Build a GLT2 container for the *complete* GLP payload.

    The plaintext is the whole payload.bin content; the engine finds the entry
    it needs by release_hash.  ``release`` is accepted for caller traceability
    and is not part of the wire format (the release string never leaves the
    server as plaintext).  ``card_key`` binds the container to the card via
    ``card_tag = SHA-256(card_key)[:16]`` in the header.  ``nonce`` defaults to
    random; pass a 12-byte value only to produce reproducible test vectors.
    """
    glp = _serialize_glp(payload_entries)
    return build_glt2_from_glp(glp, device_fp, card_key, kd, expire, nonce)


def build_glt2_from_glp(
    glp: bytes,
    device_fp: bytes,
    card_key: str | bytes,
    kd: bytes,
    expire: int,
    nonce: bytes | None = None,
    flags: int = GLT2_FLAG_AEAD,
) -> bytes:
    if len(device_fp) != 32:
        raise ValueError("device_fp must be 32 bytes")
    if not isinstance(card_key, (str, bytes)):
        raise TypeError("card_key must be str or bytes")
    if len(kd) != 32:
        raise ValueError("kd must be 32 bytes")
    if not 0 <= expire <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("expire out of u64 range")
    if isinstance(flags, bool) or not isinstance(flags, int) or not 0 <= flags <= 0xFF:
        raise ValueError("flags must be a u8 integer")
    if nonce is None:
        nonce = os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")

    card_tag = sha256(card_key)[:16]
    header = (
        GLT2_MAGIC
        + bytes([GLT2_VERSION, flags])
        + b"\x00\x00"
        + struct.pack("<Q", expire)
        + device_fp
        + card_tag
    )
    ct, tag = chacha20_poly1305_encrypt(kd, nonce, header, glp)
    return header + nonce + ct + tag


def parse_glt2_header(blob: bytes) -> dict:
    if len(blob) < GLT2_HDR_SIZE or blob[:4] != GLT2_MAGIC:
        raise ValueError("not a GLT2 file")
    version = blob[4]
    flags = blob[5]
    expire = struct.unpack_from("<Q", blob, 8)[0]
    device_fp = blob[16:48]
    card_tag = blob[48:64]
    return {
        "magic": blob[:4].decode("ascii"),
        "version": version,
        "flags": flags,
        "expire": expire,
        "device_fp": device_fp,
        "card_tag": card_tag,
    }


def decrypt_glt2(blob: bytes, kd: bytes) -> bytes:
    """Decrypt a GLT2 file with Kd, returning the plaintext GLP bytes."""
    if len(blob) < GLT2_HDR_SIZE + 12 + 16:
        raise ValueError("GLT2 file too short")
    header = blob[:GLT2_HDR_SIZE]
    parse_glt2_header(header)
    nonce = blob[GLT2_HDR_SIZE : GLT2_HDR_SIZE + 12]
    ct = blob[GLT2_HDR_SIZE + 12 : -16]
    tag = blob[-16:]
    return chacha20_poly1305_decrypt(kd, nonce, header, ct, tag)
