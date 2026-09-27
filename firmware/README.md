# TRX-1 CPU 5.9

This folder is local output. The image is produced by `whistler-trx1-decrypt` from the vendor updater. The salt and key files listed in `MANIFEST.txt` were written during the analysis. None of the binaries are committed.

`TRX1_CPU_U5.9.bin` is the 399,534-byte image after the updater's RC4-drop256. The 64-byte salt is not part of this file. SHA-256 `aaca739d8af603f841c2004e935e685860668ecc315cdb4e50a7ab17efd00632`.

These are the bytes the scanner receives, before the updater hex-encodes them on the COM port. They are not a raw CPU flash dump: the file stays at ciphertext entropy, and it has no version string. Checksums are in `MANIFEST.txt`. The write-up is `../docs/firmware.md`. The IDA notes are `../ida/out/ida-notes.md`.
