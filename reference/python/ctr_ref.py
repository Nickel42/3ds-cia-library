"""
Reference implementation of the 3ds-cia-library 3DS (CTR) format logic.

This module is the executable specification that the C# library
(3ds-cia-library) mirrors byte-for-byte. It works on in-memory byte strings,
so it is only intended for small synthetic fixtures and for cross-checking.

No Nintendo key material is contained here. All keys come from caller-supplied
boot9.bin / aes_keys.txt / seeddb.bin data.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MU = 0x200  # media unit

# ---------------------------------------------------------------- crypto ---

SCRAMBLER_C = 0x1FF9E9AAC5FE0408024591DC5D52768A
MASK128 = (1 << 128) - 1


def rol128(v: int, n: int) -> int:
    n %= 128
    return ((v << n) | (v >> (128 - n))) & MASK128


def keygen(key_x: bytes, key_y: bytes) -> bytes:
    x = int.from_bytes(key_x, 'big')
    y = int.from_bytes(key_y, 'big')
    return rol128(((rol128(x, 2) ^ y) + SCRAMBLER_C) & MASK128, 87).to_bytes(16, 'big')


def aes_ctr(key: bytes, counter: int, data: bytes) -> bytes:
    """XOR data with the AES-CTR keystream starting at 128-bit counter value."""
    c = Cipher(algorithms.AES(key), modes.CTR((counter & MASK128).to_bytes(16, 'big'))).encryptor()
    return c.update(data) + c.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ------------------------------------------------------------------ keys ---

BOOT9_KEYBLOB_OFFSET_PROT = 0x5860
BOOT9_KEYX_2C_IN_BLOB = 0x170
BOOT9_KEYX_3D_IN_BLOB = 0x1C0


@dataclass
class KeyStore:
    key_x: dict = field(default_factory=dict)      # slot -> 16 bytes
    key_y: dict = field(default_factory=dict)
    normal: dict = field(default_factory=dict)
    common_key_y: dict = field(default_factory=dict)  # index -> 16 bytes
    fixed_system_key: bytes | None = None
    seeds: dict = field(default_factory=dict)       # title id (int) -> 16 bytes

    def load_boot9(self, data: bytes, dev: bool = False) -> None:
        if len(data) not in (0x10000, 0x8000):
            raise ValueError('boot9 must be 0x10000 or 0x8000 bytes')
        base = BOOT9_KEYBLOB_OFFSET_PROT + (0x8000 if len(data) == 0x10000 else 0)
        if dev:
            base += 0x400
        self.key_x[0x2C] = data[base + BOOT9_KEYX_2C_IN_BLOB: base + BOOT9_KEYX_2C_IN_BLOB + 16]
        self.key_x[0x3D] = data[base + BOOT9_KEYX_3D_IN_BLOB: base + BOOT9_KEYX_3D_IN_BLOB + 16]

    _slot_re = re.compile(r'^slot0x([0-9A-Fa-f]{2})key([XYN])$', re.I)
    _common_re = re.compile(r'^common([0-5])$', re.I)

    def load_aes_keys_txt(self, text: str) -> None:
        for raw in text.splitlines():
            line = raw.split('#', 1)[0].strip()
            if not line or '=' not in line:
                continue
            name, value = (p.strip() for p in line.split('=', 1))
            value = value.replace(' ', '')
            if not re.fullmatch(r'[0-9A-Fa-f]{32}', value):
                continue
            key = bytes.fromhex(value)
            m = self._slot_re.match(name)
            if m:
                slot = int(m.group(1), 16)
                kind = m.group(2).upper()
                {'X': self.key_x, 'Y': self.key_y, 'N': self.normal}[kind][slot] = key
                continue
            m = self._common_re.match(name)
            if m:
                self.common_key_y[int(m.group(1))] = key
                continue
            if name.lower() == 'fixedsystemkey':
                self.fixed_system_key = key

    def load_seeddb(self, data: bytes) -> None:
        count = struct.unpack_from('<I', data, 0)[0]
        for i in range(count):
            off = 0x10 + i * 0x20
            tid = struct.unpack_from('<Q', data, off)[0]
            self.seeds[tid] = data[off + 8: off + 0x18]

    def normal_key(self, slot: int, key_y: bytes) -> bytes:
        if slot not in self.key_x:
            raise KeyError(f'missing KeyX for slot 0x{slot:02X}')
        return keygen(self.key_x[slot], key_y)

    def common_key(self, index: int) -> bytes:
        if index not in self.common_key_y:
            raise KeyError(f'missing common key Y {index}')
        return self.normal_key(0x3D, self.common_key_y[index])


# ------------------------------------------------------------------ NCCH ---

NCCH_EXTRA_SLOT = {0x00: 0x2C, 0x01: 0x25, 0x0A: 0x18, 0x0B: 0x1B}

FLAG7_FIXED = 0x01
FLAG7_NOROMFS = 0x02
FLAG7_NOCRYPTO = 0x04
FLAG7_SEED = 0x20


@dataclass
class NcchHeader:
    raw: bytes

    @property
    def magic_ok(self):
        return self.raw[0x100:0x104] == b'NCCH'

    def u32(self, off):
        return struct.unpack_from('<I', self.raw, off)[0]

    @property
    def content_size(self):
        return self.u32(0x104) * self.media_unit

    @property
    def partition_id(self):
        return struct.unpack_from('<Q', self.raw, 0x108)[0]

    @property
    def version(self):
        return struct.unpack_from('<H', self.raw, 0x112)[0]

    @property
    def program_id(self):
        return struct.unpack_from('<Q', self.raw, 0x118)[0]

    @property
    def product_code(self):
        return self.raw[0x150:0x160].split(b'\0', 1)[0].decode('ascii', 'replace')

    @property
    def exheader_size(self):
        return self.u32(0x180)

    @property
    def flags(self):
        return self.raw[0x188:0x190]

    @property
    def media_unit(self):
        return MU << self.raw[0x188 + 6]

    def region(self, off):
        return self.u32(off) * self.media_unit, self.u32(off + 4) * self.media_unit

    @property
    def logo(self):
        return self.region(0x198)

    @property
    def plain(self):
        return self.region(0x190)

    @property
    def exefs(self):
        return self.region(0x1A0)

    @property
    def exefs_hash_size(self):
        return self.u32(0x1A8) * self.media_unit

    @property
    def romfs(self):
        return self.region(0x1B0)

    @property
    def romfs_hash_size(self):
        return self.u32(0x1B8) * self.media_unit

    @property
    def is_executable(self):
        return bool(self.raw[0x18D] & 0x02)

    @property
    def no_crypto(self):
        return bool(self.flags[7] & FLAG7_NOCRYPTO)


def ncch_counter(h: NcchHeader, section: int, region_offset: int) -> int:
    """section: 1 exheader, 2 exefs, 3 romfs. Returns initial 128-bit counter."""
    if h.version == 1:
        pid = h.raw[0x108:0x110]
        b = pid + b'\0' * 4 + struct.pack('>I', region_offset)
        return int.from_bytes(b, 'big')
    return (h.partition_id << 64) | (section << 56)


@dataclass
class NcchKeys:
    key0: bytes
    key1: bytes


def ncch_keys(h: NcchHeader, ks: KeyStore) -> NcchKeys | None:
    f = h.flags
    if f[7] & FLAG7_NOCRYPTO:
        return None
    if f[7] & FLAG7_FIXED:
        if h.program_id & (0x10 << 32):
            if ks.fixed_system_key is None:
                raise KeyError('missing fixed system key')
            k = ks.fixed_system_key
        else:
            k = b'\0' * 16
        return NcchKeys(k, k)
    key_y = h.raw[0:16]
    key0 = ks.normal_key(0x2C, key_y)
    key_y1 = key_y
    if f[7] & FLAG7_SEED:
        seed = ks.seeds.get(h.program_id)
        if seed is None:
            raise KeyError(f'missing seed for {h.program_id:016X}')
        if sha256(seed + h.raw[0x118:0x120])[0:4] != h.raw[0x114:0x118]:
            raise ValueError('seed verification failed')
        key_y1 = sha256(key_y + seed)[0:16]
    slot = NCCH_EXTRA_SLOT.get(f[3])
    if slot is None:
        raise ValueError(f'unknown NCCH crypto method 0x{f[3]:02X}')
    key1 = ks.normal_key(slot, key_y1)
    return NcchKeys(key0, key1)


@dataclass
class Segment:
    start: int
    end: int
    key: int        # 0/1
    counter: int    # counter at `start`


def parse_exefs_entries(exefs_header_plain: bytes):
    out = []
    for i in range(10):
        e = exefs_header_plain[i * 16:(i + 1) * 16]
        name = e[0:8].split(b'\0', 1)[0].decode('ascii', 'replace')
        off, size = struct.unpack_from('<II', e, 8)
        if name and size:
            out.append((name, off, size))
    return out


def ncch_segments(h: NcchHeader, exefs_header_plain: bytes | None) -> list[Segment]:
    """Encrypted regions of an NCCH, sorted, non-overlapping."""
    segs: list[Segment] = []
    if h.exheader_size == 0x400:
        segs.append(Segment(0x200, 0xA00, 0, ncch_counter(h, 1, 0x200)))
    exefs_off, exefs_size = h.exefs
    if exefs_size:
        base = ncch_counter(h, 2, exefs_off)
        # split ExeFS into key0 / key1 ranges
        key1_ranges = []
        if exefs_header_plain is not None:
            for name, off, size in parse_exefs_entries(exefs_header_plain):
                if name in ('icon', 'banner'):
                    continue
                s = exefs_off + 0x200 + off
                e = min(s + size, exefs_off + exefs_size)
                key1_ranges.append((s, e))
        key1_ranges.sort()
        cur = exefs_off
        end = exefs_off + exefs_size

        def ctr_at(p):
            return base + ((p - exefs_off) >> 4)

        for s, e in key1_ranges:
            if s > cur:
                segs.append(Segment(cur, s, 0, ctr_at(cur)))
            s = max(s, cur)
            if e > s:
                segs.append(Segment(s, e, 1, ctr_at(s)))
                cur = e
        if cur < end:
            segs.append(Segment(cur, end, 0, ctr_at(cur)))
    romfs_off, romfs_size = h.romfs
    if romfs_size:
        segs.append(Segment(romfs_off, romfs_off + romfs_size, 1, ncch_counter(h, 3, romfs_off)))
    return segs


def _apply_segments(data: bytearray, segs, keys: NcchKeys):
    """XOR each segment with its keystream.

    Segment.counter is the counter of the 16-byte block that *contains*
    Segment.start (regions start on media-unit boundaries, so absolute
    16-byte alignment equals region-relative alignment). ExeFS file sizes are
    arbitrary, so key changes can fall in the middle of a block.
    """
    for s in segs:
        if s.start >= len(data):
            continue
        e = min(s.end, len(data))
        key = keys.key0 if s.key == 0 else keys.key1
        pad = s.start % 16
        chunk = b'\0' * pad + bytes(data[s.start:e])
        data[s.start:e] = aes_ctr(key, s.counter, chunk)[pad:]
    return data


def decrypted_flags(flags: bytes) -> bytes:
    f = bytearray(flags)
    f[3] = 0
    f[7] = (f[7] & ~(FLAG7_FIXED | FLAG7_SEED) & 0xFF) | FLAG7_NOCRYPTO
    return bytes(f)


def ncch_decrypt(ncch: bytes, ks: KeyStore) -> bytes:
    h = NcchHeader(ncch[:0x200])
    if not h.magic_ok:
        return ncch
    keys = ncch_keys(h, ks)
    if keys is None:
        return ncch
    exefs_off, exefs_size = h.exefs
    exefs_hdr = None
    if exefs_size:
        exefs_hdr = aes_ctr(keys.key0, ncch_counter(h, 2, exefs_off), ncch[exefs_off:exefs_off + 0x200])
    out = bytearray(ncch)
    _apply_segments(out, ncch_segments(h, exefs_hdr), keys)
    out[0x188:0x190] = decrypted_flags(h.flags)
    return bytes(out)


def ncch_encrypt(plain: bytes, ks: KeyStore, flags: bytes) -> bytes:
    """Test helper: encrypt a NoCrypto NCCH using the given target flags."""
    out = bytearray(plain)
    out[0x188:0x190] = flags
    h = NcchHeader(bytes(out[:0x200]))
    keys = ncch_keys(h, ks)
    exefs_off, exefs_size = h.exefs
    exefs_hdr = plain[exefs_off:exefs_off + 0x200] if exefs_size else None
    _apply_segments(out, ncch_segments(h, exefs_hdr), keys)
    return bytes(out)


def ncch_plain_view(ncch: bytes, ks: KeyStore | None) -> bytes | None:
    """Fully decrypted copy (None if keys missing)."""
    h = NcchHeader(ncch[:0x200])
    if h.no_crypto:
        return ncch
    try:
        return ncch_decrypt(ncch, ks)
    except KeyError:
        return None


def ncch_set_sd_flag(ncch_plain: bytes, sd: bool) -> bytes:
    """Patch exheader SD-application flag on a decrypted CXI, update exheader hash."""
    h = NcchHeader(ncch_plain[:0x200])
    if h.exheader_size != 0x400 or not h.is_executable:
        return ncch_plain
    out = bytearray(ncch_plain)
    if sd:
        out[0x200 + 0x0D] |= 0x02
    else:
        out[0x200 + 0x0D] &= ~0x02 & 0xFF
    out[0x160:0x180] = sha256(bytes(out[0x200:0x600]))
    return bytes(out)


def ncch_verify(ncch_plain: bytes) -> dict:
    h = NcchHeader(ncch_plain[:0x200])
    res = {}
    if h.exheader_size == 0x400:
        res['exheader'] = sha256(ncch_plain[0x200:0x600]) == h.raw[0x160:0x180]
    lo, ls = h.logo
    if ls and any(h.raw[0x130:0x150]):
        res['logo'] = sha256(ncch_plain[lo:lo + ls]) == h.raw[0x130:0x150]
    eo, es = h.exefs
    if es:
        res['exefs_superblock'] = sha256(ncch_plain[eo:eo + h.exefs_hash_size]) == h.raw[0x1C0:0x1E0]
        hdr = ncch_plain[eo:eo + 0x200]
        ok = True
        for i in range(10):
            e = hdr[i * 16:(i + 1) * 16]
            off, size = struct.unpack_from('<II', e, 8)
            if not e[0] or not size:
                continue
            expected = hdr[0x200 - (i + 1) * 0x20: 0x200 - i * 0x20]
            ok &= sha256(ncch_plain[eo + 0x200 + off: eo + 0x200 + off + size]) == expected
        res['exefs_files'] = ok
    ro, rs = h.romfs
    if rs:
        res['romfs_superblock'] = sha256(ncch_plain[ro:ro + h.romfs_hash_size]) == h.raw[0x1E0:0x200]
    return res


def exefs_file(ncch_plain: bytes, name: str) -> bytes | None:
    h = NcchHeader(ncch_plain[:0x200])
    eo, es = h.exefs
    if not es:
        return None
    for n, off, size in parse_exefs_entries(ncch_plain[eo:eo + 0x200]):
        if n == name:
            return ncch_plain[eo + 0x200 + off: eo + 0x200 + off + size]
    return None


# ------------------------------------------------------------------ NCSD ---

@dataclass
class Ncsd:
    raw: bytes

    @property
    def media_size(self):
        return struct.unpack_from('<I', self.raw, 0x104)[0] * MU

    @property
    def media_id(self):
        return struct.unpack_from('<Q', self.raw, 0x108)[0]

    def partitions(self):
        out = []
        for i in range(8):
            off, size = struct.unpack_from('<II', self.raw, 0x120 + i * 8)
            if size:
                out.append((i, off * MU, size * MU))
        return out

    @property
    def used_size(self):
        return max((o + s for _, o, s in self.partitions()), default=0x4000)

    @property
    def title_version(self):
        return struct.unpack_from('<H', self.raw, 0x310)[0]


def cci_decrypt(cci: bytes, ks: KeyStore) -> bytes:
    n = Ncsd(cci[:0x4000])
    out = bytearray(cci)
    for _, off, size in n.partitions():
        part = cci[off:off + size]
        if len(part) < 0x200:
            continue
        out[off:off + len(part)] = ncch_decrypt(part, ks)
    return bytes(out)


def cci_trim(cci: bytes) -> bytes:
    return cci[:Ncsd(cci[:0x4000]).used_size]


def cci_untrim(cci: bytes) -> bytes:
    n = Ncsd(cci[:0x4000])
    return cci + b'\xFF' * (n.media_size - len(cci))


def card_size_for(used: int) -> int:
    size = 128 * 1024 * 1024
    while size < used:
        size *= 2
    return size


CARD2_SAVE_THRESHOLD = 0x100000


def build_ncsd_header(title_id: int, title_version: int, partitions: list[tuple[int, int, bytes]],
                      save_size: int, used: int) -> bytes:
    """partitions: (index, size, first 0x200 bytes of output NCCH)."""
    card = card_size_for(used)
    hdr = bytearray(0x4000)
    hdr[0x100:0x104] = b'NCSD'
    struct.pack_into('<I', hdr, 0x104, card // MU)
    struct.pack_into('<Q', hdr, 0x108, title_id)
    off = 0x4000
    p0_header = None
    for idx, size, nh in partitions:
        struct.pack_into('<II', hdr, 0x120 + idx * 8, off // MU, size // MU)
        hdr[0x190 + idx * 8: 0x198 + idx * 8] = nh[0x108:0x110]
        if idx == 0:
            p0_header = nh
        off += size
    if p0_header is not None:
        hdr[0x160:0x180] = p0_header[0x160:0x180]
    card2 = save_size > CARD2_SAVE_THRESHOLD
    hdr[0x188 + 4] = 1
    hdr[0x188 + 5] = 2 if card2 else 1
    struct.pack_into('<I', hdr, 0x200, (used // MU) if card2 else 0xFFFFFFFF)
    struct.pack_into('<I', hdr, 0x300, min(used, 0xFFFFFFFF))
    struct.pack_into('<H', hdr, 0x310, title_version)
    struct.pack_into('<Q', hdr, 0x1000, title_id)
    if p0_header is not None:
        hdr[0x1100:0x1200] = p0_header[0x100:0x200]
    hdr[0x1200:0x4000] = b'\xFF' * (0x4000 - 0x1200)
    return bytes(hdr)


# ------------------------------------------------------------------- CIA ---

SIG_SIZES = {0x10000: (0x200, 0x3C), 0x10001: (0x100, 0x3C), 0x10002: (0x3C, 0x40),
             0x10003: (0x200, 0x3C), 0x10004: (0x100, 0x3C), 0x10005: (0x3C, 0x40)}


def align(v, a):
    return (v + a - 1) // a * a


def sig_block_size(blob: bytes) -> int:
    t = struct.unpack_from('>I', blob, 0)[0]
    s, p = SIG_SIZES[t]
    return 4 + s + p


@dataclass
class ContentChunk:
    id: int
    index: int
    type: int
    size: int
    hash: bytes

    def pack(self):
        return struct.pack('>IHHQ', self.id, self.index, self.type, self.size) + self.hash


@dataclass
class Tmd:
    raw: bytes
    hdr_off: int
    chunks: list

    @classmethod
    def parse(cls, raw: bytes):
        ho = sig_block_size(raw)
        count = struct.unpack_from('>H', raw, ho + 0x9E)[0]
        chunks = []
        base = ho + 0xC4 + 0x900
        for i in range(count):
            cid, idx, typ, size = struct.unpack_from('>IHHQ', raw, base + i * 0x30)
            chunks.append(ContentChunk(cid, idx, typ, size, raw[base + i * 0x30 + 0x10: base + i * 0x30 + 0x30]))
        return cls(raw, ho, chunks)

    @property
    def title_id(self):
        return struct.unpack_from('>Q', self.raw, self.hdr_off + 0x4C)[0]

    @property
    def title_version(self):
        return struct.unpack_from('>H', self.raw, self.hdr_off + 0x9C)[0]

    def rebuild(self, chunks) -> bytes:
        """Return TMD with replaced chunk records and recomputed info-record hashes."""
        out = bytearray(self.raw)
        ho = self.hdr_off
        base = ho + 0xC4 + 0x900
        for i, c in enumerate(chunks):
            out[base + i * 0x30: base + (i + 1) * 0x30] = c.pack()
        info = ho + 0xC4
        for r in range(64):
            ro = info + r * 0x24
            idx_off, cmd_count = struct.unpack_from('>HH', out, ro)
            if cmd_count == 0:
                continue
            out[ro + 4: ro + 0x24] = sha256(bytes(out[base + idx_off * 0x30: base + (idx_off + cmd_count) * 0x30]))
        out[ho + 0xA4: ho + 0xC4] = sha256(bytes(out[info: info + 0x900]))
        return bytes(out)


@dataclass
class Cia:
    raw: bytes
    cert: bytes
    ticket: bytes
    tmd: Tmd
    content_offset: int
    meta: bytes
    present: list   # list of (chunk, offset)

    @classmethod
    def parse(cls, raw: bytes):
        hsize, typ, ver, cs, ts, tms, ms = struct.unpack_from('<IHHIIII', raw, 0)
        content_size = struct.unpack_from('<Q', raw, 0x18)[0]
        bitmap = raw[0x20:0x2020]
        o = align(hsize, 64)
        cert = raw[o:o + cs]
        o = align(o + cs, 64)
        ticket = raw[o:o + ts]
        o = align(o + ts, 64)
        tmd = Tmd.parse(raw[o:o + tms])
        o = align(o + tms, 64)
        content_offset = o
        meta_off = align(o + content_size, 64)
        meta = raw[meta_off:meta_off + ms] if ms else b''
        present = []
        p = content_offset
        for c in tmd.chunks:
            if bitmap[c.index >> 3] & (0x80 >> (c.index & 7)):
                present.append((c, p))
                p += c.size
        return cls(raw, cert, ticket, tmd, content_offset, meta, present)

    def titlekey(self, ks: KeyStore) -> bytes:
        to = sig_block_size(self.ticket)
        enc = self.ticket[to + 0x7F: to + 0x8F]
        tid = self.ticket[to + 0x9C: to + 0xA4]
        idx = self.ticket[to + 0xB1]
        return aes_cbc_decrypt(ks.common_key(idx), tid + b'\0' * 8, enc)

    def content_plain_cbc(self, chunk: ContentChunk, offset: int, ks: KeyStore) -> bytes:
        data = self.raw[offset:offset + chunk.size]
        if chunk.type & 1:
            iv = struct.pack('>H', chunk.index) + b'\0' * 14
            data = aes_cbc_decrypt(self.titlekey(ks), iv, data)
        return data


def cia_decrypt(cia: bytes, ks: KeyStore) -> bytes:
    c = Cia.parse(cia)
    out = bytearray(cia)
    new_chunks = list(c.tmd.chunks)
    for chunk, off in c.present:
        data = c.content_plain_cbc(chunk, off, ks)
        if data[0x100:0x104] == b'NCCH':
            data = ncch_decrypt(data, ks)
        out[off:off + chunk.size] = data
        i = c.tmd.chunks.index(chunk)
        new_chunks[i] = ContentChunk(chunk.id, chunk.index, chunk.type & ~1 & 0xFFFF, chunk.size, sha256(data))
    hsize, typ, ver, cs, ts, tms = struct.unpack_from('<IHHIII', cia, 0)
    tmd_off = align(align(align(hsize, 64) + cs, 64) + ts, 64)
    out[tmd_off:tmd_off + tms] = c.tmd.rebuild(new_chunks)
    return bytes(out)


TICKET_ISSUER = b'Root-CA00000003-XS0000000c'
TMD_ISSUER = b'Root-CA00000003-CP0000000b'
TICKET_CONTENT_INDEX_HEADER = bytes.fromhex(
    '00010014000000AC000000140001001400000000000000280000000100000084000000840003000000000000')


def build_ticket(title_id: int, title_version: int) -> bytes:
    t = bytearray(0x350)
    struct.pack_into('>I', t, 0, 0x10004)
    d = 0x140
    t[d:d + len(TICKET_ISSUER)] = TICKET_ISSUER
    t[d + 0x7C] = 1
    struct.pack_into('>Q', t, d + 0x9C, title_id)
    struct.pack_into('>H', t, d + 0xA6, title_version)
    ci = d + 0x164
    t[ci:ci + 0x2C] = TICKET_CONTENT_INDEX_HEADER
    t[ci + 0x2C: ci + 0xAC] = b'\xFF' * 0x80
    return bytes(t)


def build_tmd(title_id: int, title_version: int, save_size: int, chunks: list) -> bytes:
    n = len(chunks)
    t = bytearray(0x140 + 0xC4 + 0x900 + 0x30 * n)
    struct.pack_into('>I', t, 0, 0x10004)
    h = 0x140
    t[h:h + len(TMD_ISSUER)] = TMD_ISSUER
    t[h + 0x40] = 1
    struct.pack_into('>Q', t, h + 0x4C, title_id)
    struct.pack_into('>I', t, h + 0x54, 0x40)
    struct.pack_into('<I', t, h + 0x5A, save_size & 0xFFFFFFFF)
    struct.pack_into('>H', t, h + 0x9C, title_version)
    struct.pack_into('>H', t, h + 0x9E, n)
    base = h + 0xC4 + 0x900
    for i, c in enumerate(chunks):
        t[base + i * 0x30: base + (i + 1) * 0x30] = c.pack()
    info = h + 0xC4
    struct.pack_into('>HH', t, info, 0, n)
    t[info + 4: info + 0x24] = sha256(bytes(t[base: base + 0x30 * n]))
    t[h + 0xA4: h + 0xC4] = sha256(bytes(t[info: info + 0x900]))
    return bytes(t)


def build_meta(ncch0_plain: bytes) -> bytes:
    h = NcchHeader(ncch0_plain[:0x200])
    if h.exheader_size != 0x400:
        return b''
    icon = exefs_file(ncch0_plain, 'icon')
    if icon is None:
        return b''
    m = bytearray(0x3AC0)
    m[0:0x180] = ncch0_plain[0x200 + 0x40: 0x200 + 0x1C0]
    struct.pack_into('<I', m, 0x300, 2)
    icon = icon[:0x36C0]
    m[0x400:0x400 + len(icon)] = icon
    return bytes(m)


def exheader_save_size(ncch_plain: bytes | None) -> int:
    if ncch_plain is None:
        return 0
    h = NcchHeader(ncch_plain[:0x200])
    if h.exheader_size != 0x400:
        return 0
    return struct.unpack_from('<Q', ncch_plain, 0x200 + 0x1C0)[0]


def _prepare_content(ncch: bytes, ks: KeyStore, decrypt: bool, sd: bool | None, index: int):
    """Return (output_bytes, plain_view_or_None)."""
    plain = ncch_plain_view(ncch, ks) if ncch[0x100:0x104] == b'NCCH' else None
    if decrypt and plain is not None:
        outb = plain
        if index == 0 and sd is not None:
            outb = ncch_set_sd_flag(outb, sd)
        return outb, outb
    # keep encryption: patch via plaintext delta (CTR is XOR, so XOR delta onto ciphertext)
    outb = ncch
    if index == 0 and sd is not None and plain is not None:
        patched = ncch_set_sd_flag(plain, sd)
        if patched != plain:
            ob = bytearray(ncch)
            ob[0x20D] ^= plain[0x20D] ^ patched[0x20D]
            ob[0x160:0x180] = patched[0x160:0x180]
            outb = bytes(ob)
            plain = patched
    return outb, plain


def cci_to_cia(cci: bytes, ks: KeyStore, decrypt: bool = True, cert_chain: bytes | None = None) -> bytes:
    n = Ncsd(cci[:0x4000])
    contents = []  # (index, bytes)
    plain0 = None
    for idx, off, size in n.partitions():
        if idx > 5:
            continue
        outb, plain = _prepare_content(cci[off:off + size], ks, decrypt, True, idx)
        if idx == 0:
            plain0 = plain
        contents.append((idx, outb))
    chunks = [ContentChunk(idx, idx, 0, len(b), sha256(b)) for idx, b in contents]
    title_id = n.media_id
    title_version = n.title_version
    cert = cert_chain if cert_chain is not None else b'\0' * 0xA00
    ticket = build_ticket(title_id, title_version)
    tmd = build_tmd(title_id, title_version, exheader_save_size(plain0), chunks)
    meta = build_meta(plain0) if plain0 is not None else b''
    content_size = sum(len(b) for _, b in contents)
    header = bytearray(0x2020)
    struct.pack_into('<IHHIIII', header, 0, 0x2020, 0, 0, len(cert), len(ticket), len(tmd), len(meta))
    struct.pack_into('<Q', header, 0x18, content_size)
    for idx, _ in contents:
        header[0x20 + (idx >> 3)] |= 0x80 >> (idx & 7)
    out = bytearray()

    def put(b):
        out.extend(b'\0' * (align(len(out), 64) - len(out)))
        out.extend(b)

    put(header)
    put(cert)
    put(ticket)
    put(tmd)
    put(b''.join(b for _, b in contents))
    if meta:
        put(meta)
    return bytes(out)


def cia_to_cci(cia: bytes, ks: KeyStore, decrypt: bool = True, trim: bool = True) -> bytes:
    c = Cia.parse(cia)
    tid = c.tmd.title_id
    if (tid >> 32) not in (0x00040000, 0x00040002):
        raise ValueError(f'title {tid:016X} is not a game application')
    parts = []
    plain0 = None
    for chunk, off in c.present:
        if chunk.index > 7:
            raise ValueError('content index > 7 cannot be placed in a CCI')
        data = c.content_plain_cbc(chunk, off, ks)
        if data[0x100:0x104] != b'NCCH':
            raise ValueError('content is not NCCH')
        outb, plain = _prepare_content(data, ks, decrypt, False, chunk.index)
        outb = outb + b'\xFF' * (align(len(outb), MU) - len(outb))
        if chunk.index == 0:
            plain0 = plain
        parts.append((chunk.index, outb))
    if not any(i == 0 for i, _ in parts):
        raise ValueError('CIA has no content 0')
    parts.sort()
    used = 0x4000 + sum(len(b) for _, b in parts)
    hdr = build_ncsd_header(tid, c.tmd.title_version,
                            [(i, len(b), b[:0x200]) for i, b in parts],
                            exheader_save_size(plain0), used)
    out = bytearray(hdr)
    for _, b in parts:
        out.extend(b)
    if not trim:
        out.extend(b'\xFF' * (card_size_for(used) - len(out)))
    return bytes(out)


# --------------------------------------------------------------- hashing ---

def crc32(b: bytes) -> int:
    import zlib
    return zlib.crc32(b) & 0xFFFFFFFF


def all_hashes(b: bytes) -> dict:
    return {'size': len(b), 'crc32': f'{crc32(b):08x}', 'md5': hashlib.md5(b).hexdigest(),
            'sha1': hashlib.sha1(b).hexdigest(), 'sha256': hashlib.sha256(b).hexdigest()}
