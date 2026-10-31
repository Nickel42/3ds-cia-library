"""
Generate synthetic 3DS test fixtures with FAKE keys and record the expected
results of every operation, as computed by ctr_ref.py.

Usage: python3 -I gen_fixtures.py <output-dir>

Everything is deterministic (seeded PRNG), so re-running produces identical
files. The fake keys are random bytes and have nothing to do with real keys.
"""
from __future__ import annotations

import json
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctr_ref as R  # noqa: E402

rng = random.Random(0x3D5)


def rbytes(n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


# ------------------------------------------------------------ fake keys ---

def make_keys():
    boot9 = bytearray(rbytes(0x10000))
    kx2c = rbytes(16)
    kx3d = rbytes(16)
    base = 0x8000 + R.BOOT9_KEYBLOB_OFFSET_PROT
    boot9[base + R.BOOT9_KEYX_2C_IN_BLOB: base + R.BOOT9_KEYX_2C_IN_BLOB + 16] = kx2c
    boot9[base + R.BOOT9_KEYX_3D_IN_BLOB: base + R.BOOT9_KEYX_3D_IN_BLOB + 16] = kx3d
    aes_lines = ['# FAKE TEST KEYS - not real 3DS keys',
                 f'slot0x25KeyX={rbytes(16).hex().upper()}',
                 f'slot0x18KeyX={rbytes(16).hex().upper()}',
                 f'slot0x1BKeyX={rbytes(16).hex().upper()}']
    for i in range(6):
        aes_lines.append(f'common{i}={rbytes(16).hex().upper()}')
    aes_lines.append(f'fixedSystemKey={rbytes(16).hex().upper()}')
    aes_txt = '\n'.join(aes_lines) + '\n'
    return bytes(boot9), aes_txt


# -------------------------------------------------------- NCCH builder ---

def smdh(short: str, long: str, publisher: str) -> bytes:
    s = bytearray(0x36C0)
    s[0:4] = b'SMDH'
    for lang in range(16):
        o = 8 + lang * 0x200
        for text, off, size in ((short, 0, 0x80), (long, 0x80, 0x100), (publisher, 0x180, 0x80)):
            enc = text.encode('utf-16-le')[:size]
            s[o + off:o + off + len(enc)] = enc
    s[0x2000:0x36C0] = rbytes(0x36C0 - 0x2000)
    return bytes(s)


def build_ncch_plain(*, title_id: int, product: str, executable: bool, version: int = 2,
                     save_size: int = 0x80000, sd_flag: bool = False,
                     code_size: int = 0x1234, romfs_size: int = 0x3000,
                     icon: bytes | None = None, title: str = 'TESTGAME',
                     seed: bytes | None = None, content_type: int = 0) -> bytes:
    hdr = bytearray(0x200)
    hdr[0:0x100] = rbytes(0x100)          # signature; first 16 bytes = KeyY
    hdr[0x100:0x104] = b'NCCH'
    struct.pack_into('<Q', hdr, 0x108, title_id)
    hdr[0x110:0x112] = b'01'
    struct.pack_into('<H', hdr, 0x112, version)
    struct.pack_into('<Q', hdr, 0x118, title_id)
    hdr[0x150:0x150 + len(product)] = product.encode('ascii')
    body = bytearray()
    cur = 0x200

    def put(b: bytes):
        nonlocal cur
        body.extend(b)
        cur += len(b)

    if executable:
        exh = bytearray(0x800)
        exh[0:len(title)] = title.encode('ascii')
        exh[0x0D] = 0x02 if sd_flag else 0x00
        exh[0x40:0x1C0] = rbytes(0x180)
        struct.pack_into('<Q', exh, 0x1C0, save_size)
        exh[0x200:0x800] = rbytes(0x600)
        struct.pack_into('<I', hdr, 0x180, 0x400)
        hdr[0x160:0x180] = R.sha256(bytes(exh[0:0x400]))
        put(bytes(exh))
        # logo
        logo = rbytes(0x2000)
        struct.pack_into('<II', hdr, 0x198, cur // R.MU, len(logo) // R.MU)
        hdr[0x130:0x150] = R.sha256(logo)
        put(logo)
        # plain region
        plain = b'[SDK+NINTENDO:Fake]' + b'\0' * (0x200 - 19)
        struct.pack_into('<II', hdr, 0x190, cur // R.MU, 1)
        put(plain)
        # exefs
        files = [('.code', rbytes(code_size)), ('banner', rbytes(0x400)),
                 ('icon', icon if icon is not None else smdh('Test', 'Test', 'NoIntrovert'))]
        exhdr = bytearray(0x200)
        data = bytearray()
        for i, (name, content) in enumerate(files):
            off = len(data)
            exhdr[i * 16:i * 16 + len(name)] = name.encode()
            struct.pack_into('<II', exhdr, i * 16 + 8, off, len(content))
            exhdr[0x200 - (i + 1) * 0x20: 0x200 - i * 0x20] = R.sha256(content)
            data.extend(content)
            data.extend(b'\0' * (R.align(len(data), 0x200) - len(data)))
        exefs = bytes(exhdr) + bytes(data)
        struct.pack_into('<III', hdr, 0x1A0, cur // R.MU, len(exefs) // R.MU, 1)
        hdr[0x1C0:0x1E0] = R.sha256(exefs[:0x200])
        put(exefs)
        flags5 = 0x03 | (content_type << 2)
    else:
        flags5 = 0x01 | (content_type << 2)
    # romfs (fake IVFC-looking blob)
    romfs = bytearray(rbytes(romfs_size))
    romfs[0:4] = b'IVFC'
    romfs = bytes(romfs)
    struct.pack_into('<III', hdr, 0x1B0, cur // R.MU, len(romfs) // R.MU, 1)
    hdr[0x1E0:0x200] = R.sha256(romfs[:0x200])
    put(romfs)
    struct.pack_into('<I', hdr, 0x104, cur // R.MU)
    hdr[0x188 + 4] = 1
    hdr[0x188 + 5] = flags5
    hdr[0x188 + 7] = R.FLAG7_NOCRYPTO
    if seed is not None:
        struct.pack_into('<I', hdr, 0x114, struct.unpack_from('<I', R.sha256(seed + bytes(hdr[0x118:0x120])), 0)[0])
    return bytes(hdr) + bytes(body)


def enc_flags(crypto_method: int, flag7: int, content_flags5: int) -> bytes:
    f = bytearray(8)
    f[3] = crypto_method
    f[4] = 1
    f[5] = content_flags5
    f[7] = flag7
    return bytes(f)


# ----------------------------------------------------------- builders ---

def build_cia_encrypted(contents: list[tuple[int, bytes]], title_id: int, title_version: int,
                        ks: R.KeyStore, common_index: int) -> bytes:
    """Build a retail-style CIA: CBC-encrypted contents with an encrypted titlekey."""
    titlekey = rbytes(16)
    ticket = bytearray(R.build_ticket(title_id, title_version))
    d = 0x140
    enc_tk = R.aes_cbc_encrypt(ks.common_key(common_index), struct.pack('>Q', title_id) + b'\0' * 8, titlekey)
    ticket[d + 0x7F:d + 0x8F] = enc_tk
    ticket[d + 0xB1] = common_index
    chunks = []
    blobs = []
    for idx, data in contents:
        chunks.append(R.ContentChunk(0x10 + idx, idx, 0x0001, len(data), R.sha256(data)))
        iv = struct.pack('>H', idx) + b'\0' * 14
        blobs.append(R.aes_cbc_encrypt(titlekey, iv, data))
    plain0 = R.ncch_plain_view(contents[0][1], ks)
    tmd = R.build_tmd(title_id, title_version, R.exheader_save_size(plain0), chunks)
    cert = rbytes(0xA00)
    meta = R.build_meta(plain0)
    header = bytearray(0x2020)
    struct.pack_into('<IHHIIII', header, 0, 0x2020, 0, 0, len(cert), len(ticket), len(tmd), len(meta))
    struct.pack_into('<Q', header, 0x18, sum(len(b) for b in blobs))
    for idx, _ in contents:
        header[0x20 + (idx >> 3)] |= 0x80 >> (idx & 7)
    out = bytearray()

    def put(b):
        out.extend(b'\0' * (R.align(len(out), 64) - len(out)))
        out.extend(b)
    put(header)
    put(cert)
    put(bytes(ticket))
    put(tmd)
    put(b''.join(blobs))
    put(meta)
    return bytes(out), cert


def build_cci(parts: list[tuple[int, bytes]], title_id: int, title_version: int, save_size: int) -> bytes:
    used = 0x4000 + sum(len(b) for _, b in parts)
    hdr = bytearray(R.build_ncsd_header(title_id, title_version, [(i, len(b), b[:0x200]) for i, b in parts],
                                        save_size, used))
    hdr[0:0x100] = rbytes(0x100)                      # "signature"
    hdr[0x1000 + 0x10:0x1000 + 0x3C] = rbytes(0x2C)    # fake InitialData crypto blob
    out = bytearray(hdr)
    for _, b in parts:
        out.extend(b)
    return bytes(out)


# --------------------------------------------------------------- main ---

def main(outdir: str):
    os.makedirs(outdir, exist_ok=True)
    boot9, aes_txt = make_keys()
    ks = R.KeyStore()
    ks.load_boot9(boot9)
    ks.load_aes_keys_txt(aes_txt)

    # --- Game A: retail cart (CCI), CXI uses 7.x crypto (slot 0x25), manual uses v1 counters
    tid_a = 0x0004000000ABCD00
    cxi_a_plain = build_ncch_plain(title_id=tid_a, product='CTR-P-ATGE', executable=True,
                                   icon=smdh('Test Game', 'Test Game: Long Title', 'NoIntrovert Labs'),
                                   save_size=0x80000)
    cfa_a_plain = build_ncch_plain(title_id=tid_a | 0x0000000000000000, product='CTR-P-ATGE', executable=False,
                                   version=1, content_type=2, romfs_size=0x2000)
    # give the manual a distinct partition id like real carts do
    cfa_a_plain = bytearray(cfa_a_plain)
    struct.pack_into('<Q', cfa_a_plain, 0x108, tid_a | 0x0001000000000000)
    cfa_a_plain = bytes(cfa_a_plain)
    cxi_a = R.ncch_encrypt(cxi_a_plain, ks, enc_flags(0x01, 0x00, 0x03))
    cfa_a = R.ncch_encrypt(cfa_a_plain, ks, enc_flags(0x00, 0x00, 0x09))
    cci_a = build_cci([(0, cxi_a), (1, cfa_a)], tid_a, 0x0410, 0x80000)

    # --- Game B: eShop CIA, seed crypto + New3DS 9.3 slot 0x18, encrypted titlekey (common key 1)
    tid_b = 0x0004000000BEEF00
    seed_b = rbytes(16)
    ks.seeds[tid_b] = seed_b
    cxi_b_plain = build_ncch_plain(title_id=tid_b, product='CTR-N-BSDJ', executable=True, sd_flag=True,
                                   icon=smdh('Seed Game', 'Seed Game Long', 'NoIntrovert Labs'),
                                   save_size=0x200000, seed=seed_b, code_size=0x2001)
    cfa_b_plain = build_ncch_plain(title_id=tid_b, product='CTR-N-BSDJ', executable=False, content_type=2,
                                   romfs_size=0x1800)
    cxi_b = R.ncch_encrypt(cxi_b_plain, ks, enc_flags(0x0A, R.FLAG7_SEED, 0x03))
    cfa_b = R.ncch_encrypt(cfa_b_plain, ks, enc_flags(0x00, 0x00, 0x09))
    cia_b, cert_b = build_cia_encrypted([(0, cxi_b), (1, cfa_b)], tid_b, 0x0020, ks, 1)

    # seeddb
    seeddb = struct.pack('<I', 1) + b'\0' * 12 + struct.pack('<Q', tid_b) + seed_b + b'\0' * 8

    # --- Fixed-key system CXI (standalone .cxi)
    tid_c = 0x0004001000C0FF00   # system category bit (0x10 << 32)
    cxi_c_plain = build_ncch_plain(title_id=tid_c, product='CTR-P-CSYS', executable=True)
    cxi_c = R.ncch_encrypt(cxi_c_plain, ks, enc_flags(0x00, R.FLAG7_FIXED, 0x03))
    tid_d = 0x0004000000D0D000
    cxi_d_plain = build_ncch_plain(title_id=tid_d, product='CTR-P-DZRO', executable=True, code_size=0x777)
    cxi_d = R.ncch_encrypt(cxi_d_plain, ks, enc_flags(0x00, R.FLAG7_FIXED, 0x03))

    # sanity: decrypting gives back the plain NCCH (except flags, which are normalized)
    for enc, plain in ((cxi_a, cxi_a_plain), (cfa_a, cfa_a_plain), (cxi_b, cxi_b_plain),
                       (cfa_b, cfa_b_plain), (cxi_c, cxi_c_plain), (cxi_d, cxi_d_plain)):
        dec = R.ncch_decrypt(enc, ks)
        assert dec[:0x188] == plain[:0x188] and dec[0x190:] == plain[0x190:], 'decrypt mismatch'
        assert dec[0x188 + 7] & R.FLAG7_NOCRYPTO and dec[0x188 + 3] == 0
        assert all(R.ncch_verify(dec).values()), R.ncch_verify(dec)
        assert enc != plain

    files = {
        'keys/boot9_fake.bin': boot9,
        'keys/aes_keys_fake.txt': aes_txt.encode(),
        'keys/seeddb_fake.bin': seeddb,
        'keys/certs_fake.bin': cert_b,
        'game_a.3ds': cci_a,
        'game_b.cia': cia_b,
        'system_fixed.cxi': cxi_c,
        'zero_fixed.cxi': cxi_d,
    }

    # ---------------------------------------------------- operations ---
    results = {}

    def record(name, data, **extra):
        files[f'expected/{name}'] = data
        results[name] = dict(R.all_hashes(data), **extra)

    a_dec = R.cci_decrypt(cci_a, ks)
    record('game_a.decrypted.3ds', a_dec)
    a_untrim_hashes = R.all_hashes(R.cci_untrim(cci_a))
    a_dec_untrim_hashes = R.all_hashes(R.cci_untrim(a_dec))
    results['game_a.untrimmed.3ds'] = a_untrim_hashes
    results['game_a.decrypted.untrimmed.3ds'] = a_dec_untrim_hashes
    assert R.cci_trim(R.cci_untrim(cci_a)) == cci_a

    a_cia = R.cci_to_cia(cci_a, ks, decrypt=True, cert_chain=cert_b)
    record('game_a.cia', a_cia)
    a_cia_enc = R.cci_to_cia(cci_a, ks, decrypt=False, cert_chain=cert_b)
    record('game_a.keepenc.cia', a_cia_enc)
    a_cia_nocert = R.cci_to_cia(cci_a, ks, decrypt=True, cert_chain=None)
    record('game_a.nocert.cia', a_cia_nocert)

    b_dec = R.cia_decrypt(cia_b, ks)
    record('game_b.decrypted.cia', b_dec)
    b_cci = R.cia_to_cci(cia_b, ks, decrypt=True, trim=True)
    record('game_b.3ds', b_cci)
    b_cci_enc = R.cia_to_cci(cia_b, ks, decrypt=False, trim=True)
    record('game_b.keepenc.3ds', b_cci_enc)
    results['game_b.untrimmed.3ds'] = R.all_hashes(R.cia_to_cci(cia_b, ks, decrypt=True, trim=False))

    record('system_fixed.decrypted.cxi', R.ncch_decrypt(cxi_c, ks))
    record('zero_fixed.decrypted.cxi', R.ncch_decrypt(cxi_d, ks))

    # ------------------------------------------------- self checks ---
    # TMD hashes of a converted CIA match its contents, and NCCH internals verify
    for blob in (a_cia, b_dec):
        c = R.Cia.parse(blob)
        for chunk, off in c.present:
            assert R.sha256(blob[off:off + chunk.size]) == chunk.hash
            assert all(R.ncch_verify(blob[off:off + chunk.size]).values())
    # SD flag set in CIA, cleared in CCI
    c = R.Cia.parse(a_cia)
    assert a_cia[c.present[0][1] + 0x20D] & 2
    assert b_cci[0x4000 + 0x20D] & 2 == 0
    assert all(R.ncch_verify(b_cci[0x4000:]).values())
    # keep-encryption outputs decrypt to the same thing as decrypted outputs
    # (the InitialData copy of the NCCH header at 0x1100 keeps the encrypted flags;
    #  CCI decryption deliberately only touches partitions)
    assert R.cci_decrypt(b_cci_enc, ks)[0x4000:] == b_cci[0x4000:]
    assert R.cia_decrypt(a_cia_enc, ks)[R.Cia.parse(a_cia).content_offset:] == a_cia[R.Cia.parse(a_cia).content_offset:]
    # round trip: CCI -> CIA -> CCI gives back the decrypted, trimmed CCI's partitions
    rt = R.cia_to_cci(a_cia, ks)
    for (i1, o1, s1), (i2, o2, s2) in zip(R.Ncsd(rt).partitions(), R.Ncsd(a_dec).partitions()):
        assert rt[o1:o1 + s1] == a_dec[o2:o2 + s2], 'round trip partition mismatch'
    assert R.Ncsd(b_cci).raw[0x188 + 5] == 2, 'save > 1 MiB should be CARD2'
    assert R.Ncsd(a_dec).raw[0x188 + 5] == 1

    # identification facts the C# tests also assert
    results['_facts'] = {
        'game_a_title_id': f'{tid_a:016X}', 'game_a_product': 'CTR-P-ATGE',
        'game_a_title': 'Test Game', 'game_a_publisher': 'NoIntrovert Labs',
        'game_b_title_id': f'{tid_b:016X}', 'game_b_product': 'CTR-N-BSDJ',
        'game_a_media_size': R.Ncsd(cci_a).media_size, 'game_a_used_size': R.Ncsd(cci_a).used_size,
        'scrambler_x': bytes(range(16)).hex(), 'scrambler_y': bytes(range(16, 32)).hex(),
        'scrambler_normal': R.keygen(bytes(range(16)), bytes(range(16, 32))).hex(),
    }

    # ------------------------------------------------------- DAT files ---
    ua = a_untrim_hashes
    ub = R.all_hashes(cia_b)
    dat_xml = f'''<?xml version="1.0"?>
<!DOCTYPE datafile PUBLIC "-//Logiqx//DTD ROM Management Datafile//EN" "http://www.logiqx.com/dtds/datafile.dtd">
<datafile>
\t<header>
\t\t<name>Nintendo - Nintendo 3DS (Encrypted) [FAKE TEST DAT]</name>
\t\t<description>Synthetic test DAT</description>
\t\t<version>20261030-000000</version>
\t</header>
\t<game name="Test Game (USA)" id="0001">
\t\t<description>Test Game (USA)</description>
\t\t<rom name="Test Game (USA).3ds" size="{ua['size']}" crc="{ua['crc32'].upper()}" md5="{ua['md5']}" sha1="{ua['sha1']}" sha256="{ua['sha256']}" serial="CTR-P-ATGE" status="verified"/>
\t</game>
\t<game name="Seed Game (Japan) (eShop)" id="0002">
\t\t<description>Seed Game (Japan) (eShop)</description>
\t\t<rom name="Seed Game (Japan) (eShop).cia" size="{ub['size']}" crc="{ub['crc32']}" sha1="{ub['sha1']}"/>
\t</game>
\t<game name="Unrelated &amp; Other (Europe)">
\t\t<description>Unrelated</description>
\t\t<rom name="Unrelated &amp; Other (Europe).3ds" size="134217728" crc="00000000" sha1="0000000000000000000000000000000000000000" serial="CTR-P-ZZZP"/>
\t</game>
</datafile>
'''
    da = R.all_hashes(R.cci_untrim(a_dec))
    dat_cmp = f'''clrmamepro (
\tname "Nintendo - Nintendo 3DS (Decrypted) [FAKE TEST DAT]"
\tdescription "Synthetic test DAT"
\tversion 20261030
)

game (
\tname "Test Game (USA)"
\tdescription "Test Game (USA)"
\trom ( name "Test Game (USA).3ds" size {da['size']} crc {da['crc32'].upper()} md5 {da['md5'].upper()} sha1 {da['sha1'].upper()} serial "CTR-P-ATGE" )
)
'''
    files['dats/fake_3ds_encrypted.dat'] = dat_xml.encode()
    files['dats/fake_3ds_decrypted.dat'] = dat_cmp.encode()

    for rel, data in files.items():
        p = os.path.join(outdir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f:
            f.write(data)
    with open(os.path.join(outdir, 'expected.json'), 'w') as f:
        json.dump(results, f, indent=2, sort_keys=True)
    print(f'wrote {len(files)} files to {outdir}')
    for k, v in sorted(results.items()):
        if not k.startswith('_'):
            print(f"  {k:40s} {v['size']:>10d}  {v['sha256'][:16]}")


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'fixtures')
