# Third-party notices

This code is original. No third-party source code is included.

Format and crypto behaviour follows public documentation and was cross-checked against these open-source projects:

- **3dbrew.org** — NCSD, NCCH, CIA, Ticket, TMD and AES key scrambler documentation.
- **pyctr** by Ian Burgwin (MIT License) — reference for NCCH key selection, counters, the ExeFS key split, seed handling and boot9 keyblob offsets. The two retail boot9 SHA-256 values in `CtrKeyStore` (used only to validate user-supplied files) come from it.
- **3dsconv** by Ian Burgwin (MIT License) — reference for the CCI→CIA layout (ticket/TMD fields, exheader SD flag, meta section).
- **Project_CTR** (ctrtool/makerom) by jakcron — reference for format details.

No Nintendo keys, certificates or other copyrighted Nintendo material are included. Test fixtures use randomly generated fake keys.
