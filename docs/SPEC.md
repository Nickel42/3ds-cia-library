# 3DS format behaviour — specification and design decisions

`reference/python/ctr_ref.py` is the executable form of this document. The C# library must produce byte-identical output to it, and the test suite enforces that.

## Keys

| Item | Source |
|---|---|
| KeyX 0x2C | boot9 keyblob + 0x170. The keyblob is at 0x5860 in the protected half (0xD860 in a full 0x10000-byte dump); dev units +0x400. |
| KeyX 0x3D | boot9 keyblob + 0x1C0 |
| KeyX 0x25 / 0x18 / 0x1B | aes_keys.txt `slot0xNNKeyX` |
| Common KeyY 0–5 | aes_keys.txt `common0`..`common5` |
| Fixed system key | aes_keys.txt `fixedSystemKey` (only for debug system titles) |
| Seeds | seeddb.bin: u32 count, 12 pad, entries of {u64 title ID, 16-byte seed, 8 pad} |

Key scrambler: `Normal = ROL128((ROL128(X, 2) XOR Y) + 0x1FF9E9AAC5FE0408024591DC5D52768A, 87)`, with 128-bit big-endian values.

## NCCH decryption

- **Primary key** (key 0): KeyX 0x2C + KeyY = signature[0:16]. It covers the extended header (0x200..0xA00, 0x800 bytes, present when header 0x180 == 0x400), the ExeFS header, the `icon` and `banner` files, and all ExeFS padding between files.
- **Secondary key** (key 1): the KeyX slot comes from flags[3] (0x00→0x2C, 0x01→0x25, 0x0A→0x18, 0x0B→0x1B). It covers every other ExeFS file (`.code`, etc.) and the entire RomFS.
- **Seed** (flags[7] & 0x20): KeyY1 = SHA-256(KeyY || seed)[0:16]. The seed is checked with SHA-256(seed || programId LE)[0:4] == header[0x114:0x118].
- **Fixed key** (flags[7] & 0x01): both keys are the fixed system key when programId & (0x10 << 32), otherwise all zeros.
- **Counter, versions 0 and 2**: `(partitionId << 64) | (section << 56)`, with section 1 = exheader, 2 = ExeFS, 3 = RomFS.
- **Counter, version 1**: partition ID bytes as stored, then 4 zero bytes, then the region offset as a big-endian u32.
- The counter at position p of a region = base + (p − regionStart) / 16. ExeFS key boundaries can fall mid-block, so each block uses whichever key owns each of its bytes.
- **After decryption**: flags[3] = 0, flags[7] &= ~(0x01 | 0x20), flags[7] |= 0x04. No other header bytes change, and the header hashes stay valid because they cover plaintext.

## CCI decryption

Every NCSD partition that is an NCCH is decrypted in place. All other bytes are copied unchanged, including the header area and the InitialData copy of the NCCH header at 0x1100, which keeps its original flags. A trimmed input stays trimmed.

## Extended header "SD application" flag

Exheader byte 0x0D, bit 0x02. It is **set** when converting to CIA and **cleared** when converting to CCI, as 3dsconv does. It only applies to content/partition 0 when that NCCH has an extended header and is executable. The exheader hash at header 0x160 (SHA-256 of the 0x400-byte exheader) is updated.

When NCCH encryption is kept, the change is applied by XOR-ing the plaintext delta into the ciphertext byte at 0x20D. AES-CTR makes that exact. This needs the primary key.

## CCI → CIA

- **Contents:** one per partition 0–5, with content ID = index = partition index. Partitions 6 and 7 (system update data) are skipped with a warning.
- **Archive header:** 0x2020 bytes with the content index bitmap set for the present indexes. Each section (header, certs, ticket, TMD, content, meta) starts on a 64-byte boundary with zero padding. Contents are concatenated, and nothing follows the last section.
- **Certificate chain:** caller or key store supplied, else 0xA00 zero bytes plus a warning.
- **Ticket** (0x350 bytes): signature type 0x00010004 with a zero signature. Issuer `Root-CA00000003-XS0000000c`, format version 1, title key zero, title ID and title version (BE), common key index 0. Content index header `00010014 000000AC 00000014 00010014 00000000 00000028 00000001 00000084 00000084 00030000 00000000`, then 0x80 × 0xFF.
- **TMD:** signature type 0x00010004 with a zero signature. Issuer `Root-CA00000003-CP0000000b`, version 1, title ID, title type 0x40, save data size (u32 LE, from exheader 0x1C0), title version (from NCSD 0x310), content count.
  - Content info record 0 = {0, count, SHA-256 of all chunk records}. The header hash at 0xA4 is the SHA-256 of the 0x900 info records.
  - Chunk records: {id, index, type 0, size, SHA-256 of the content as written}.
- **Meta** (0x3AC0 bytes, only when the exheader and icon are readable): exheader[0x40:0x1C0] dependency list, core version u32 = 2 at 0x300, and the SMDH icon at 0x400.
- **Title ID** = NCSD media ID.

## CIA → CCI

- **Allowed titles:** title ID high 0x00040000 (application) or 0x00040002 (demo). Updates, DLC and system titles are rejected.
- **Contents:** each is CIA-decrypted (AES-CBC, title key, IV = index BE u16 + 14 zero bytes) and must be an NCCH with index ≤ 7. Content 0 is required.
- **Layout:** partitions in index order, back to back from 0x4000, each padded with 0xFF to 0x200.
- **NCSD header (0x4000 bytes):**

| Offset | Value |
|---|---|
| 0x000 | Signature: zeros |
| 0x100 | `NCSD` |
| 0x104 | Card size / 0x200. Card size is the smallest of 128 MiB × 2ⁿ that holds the data. |
| 0x108 | Title ID |
| 0x110 | FS types: zeros |
| 0x118 | Crypt types: zeros |
| 0x120 | Partition table, in media units |
| 0x160 | Copy of partition 0's NCCH header 0x160 (exheader hash) |
| 0x188 | flags[4] = 1 (CTR); flags[5] = 2 (CARD2) if save size > 1 MiB, else 1 (CARD1); other flags 0 |
| 0x190 | Partition IDs, copied from each NCCH header |
| 0x200 | Writable address: CARD1 = 0xFFFFFFFF, CARD2 = used size / 0x200 |
| 0x300 | Filled size = used bytes |
| 0x310 | Title version |
| 0x1000 | InitialData: title ID (LE u64), then zeros. The title key and MAC are unknown and left zero. |
| 0x1100 | Partition 0 NCCH header bytes 0x100..0x200, as written |
| 0x1200–0x3FFF | 0xFF, as retail cards read |

- **Output size:** trimmed (end of last partition) by default, or padded with 0xFF to the card size.

## CIA decryption

- **Unchanged:** the archive header, certificates, ticket and meta, and the offsets of every section.
- **Contents:** each is CBC-decrypted, and its NCCH is decrypted as well.
- **TMD:** the chunk type loses bit 0x1, the chunk hash becomes the SHA-256 of the new content, and every content info record hash plus the header hash are recomputed. The signature is now invalid, so the CIA is fakesigned.

## Trim / untrim

Trim keeps bytes [0, end of last partition). Untrim appends 0xFF up to the media size in NCSD 0x104.

## Verification

- **Whole-file hashes:** CRC32, MD5, SHA-1 and SHA-256 in one pass. For a trimmed CCI, a second hash set covers the bytes plus virtual 0xFF padding up to the media size.
- **DAT lookup order:**
  1. SHA-256, SHA-1 or MD5 match, with size checked if the DAT lists one.
  2. CRC32 + size, but only when no stronger hash is available on both sides to disagree.
  3. Product-code (serial) match. This is not a verification, but it is used for naming.
- **Verdicts:**
  - `Bad`: any internal hash failed.
  - `Verified` / `VerifiedUntrimmed`: hash match.
  - `IntactNotInDat`: all internal checks passed but no hash match.
  - `Unknown`: no hash match, and some checks were skipped or none were run.

## Missing keys

With `Decrypt = true`, a missing key throws `MissingKeyException`; the C# code never writes partially decrypted output. The Python reference instead passes such contents through still encrypted, but no test covers that path. With `Decrypt = false`, a missing NCCH key only produces a warning, and the content is copied unchanged without the SD-flag or meta update.

## Known limitations (intentional for this RC)

- **No re-encryption:** decrypted → encrypted conversion is not supported. The original flags are lost on decryption, and nothing downstream needs it.
- **No Z3DS:** Azahar's compressed formats (.zcci/.zcia/.zcxi) are not supported yet.
- **DSiWare:** SRL contents in CIAs are CBC-decrypted and hash-checked, but not parsed.
- **RomFS:** only the superblock (IVFC header and master hash) is verified, not every IVFC level. Full integrity of a CIA is still covered by the TMD content hashes.
- **Decrypted DAT matching is unconfirmed:** No-Intro's *Decrypted* DAT is believed to follow GodMode9's flag convention, which this library implements. Byte-exact agreement with that DAT has not yet been confirmed on real dumps.
- **CCI headers from CIAs** cannot be authentic. Signature, card unique data and save crypto flags are placeholders. They work for emulators and flashcarts/CFW that accept CIA-derived CCIs, but not for reproducing original dumps.
