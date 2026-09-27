# TRX-1 CPU firmware from CPUUpdater_TRX1_U5.9

The updater analysed here is the GRE / Whistler CPU update utility, file version 0.0.1.4, copyright 2007–2010 GRE. This build carries the Whistler TRX-1 CPU application, version 5.9. The original `CPUUpdater_TRX1_U5.9.exe` is unchanged and is not in the repository.

IDA Professional 9.1 decompiled the send path and the cipher. Hex-Rays output is `ida\out\hexrays.txt`. The Python extractor used during the analysis is `tools\extract_fw.py`. The release tool is `whistler-trx1-decrypt` in `src\`.

## Result

| File | What it is | Size | SHA-256 |
| --- | --- | --- | --- |
| `TRX1_CPU_U5.9.bin` | CPU image after the updater cipher. These are the bytes the scanner receives. | 399,534 (0x618AE) | `aaca739d8af603f841c2004e935e685860668ecc315cdb4e50a7ab17efd00632` |

`TRX1_CPU_U5.9.bin` is the update image with the PC-side cipher removed. It is not a plain CPU instruction dump. Every 4 KB block has entropy about 7.95, and there is no version string. The updater never unwraps the image itself: the version and the model are stored in the clear beside it. A further bootloader transform, if the scanner applies one, is not in this executable. IDA did not find a second cipher, an AES S-box, or a CRC-16 table.

## Where the image sits

PE32, image base `0x400000`. The firmware is not a resource. It is a header plus payload in `.rdata`.

| Field | File offset | VA | Value |
| --- | --- | --- | --- |
| Platform | 0x1A618 | 0x41A618 | `0xE3` (TRX-1) |
| Version | 0x1A619 | 0x41A619 | `0x59` (5.9) |
| Length | 0x1A61C | 0x41A61C | `0x000618AE` (399,534). Bit 31 is clear, so the cipher runs. |
| Salt | 0x1A620 | 0x41A620 | 64 bytes |
| Image | 0x1A660 | 0x41A660 | 399,534 bytes |

The length dword is the image size. The salt is extra and is not counted in it. Bit 31 of the length, when set, skips the cipher and sends 64 extra bytes from the start of the payload. This file does not set that bit.

Updater SHA-256: `7132ae56c216664ad17942d23b462bd549019b3918f0cedcdaa177287d61cf96`.

## Cipher

Two functions, confirmed by Hex-Rays.

`sub_401490` selects a 64-byte static key from the platform byte: index = platform − `0xE0`, null above 10, otherwise a jump through an 11-entry table whose cases each load one key address. This executable’s platform byte is the constant `0xE3`, so Hex-Rays collapses the switch to the TRX-1 key. The key is read from the executable. It is not reproduced here.

`sub_401500` builds an RC4 state:

1. XOR the 64-byte salt with that static key. The XOR is on a stack copy. The key in the executable is not modified.
2. RC4 key schedule using that 64-byte result. The index mask is `length - 1` (`0x3F`), which is a 64-byte modulus.
3. Run the PRGA for 256 bytes and discard the keystream (RC4-drop256). The resulting `i` and `j` are stored at state+0x100 and state+0x104.

`sub_4015B0` is the PRGA. It XORs the image in place, continuing the same state. The send loop walks the image in 64-byte chunks and does not re-key.

The salt is not transmitted. It only mixes the RC4 key. The scanner therefore receives the RC4 output, not the salt and not the bytes as they sit in the executable.

## Model bytes

The same platform byte picks the model name and the key. Names are the ASCII strings at file `0xA019C`.

| Platform | Model | Cipher |
| --- | --- | --- |
| 0xE0 | TRX-2e | yes |
| 0xE1 | TRX-1e | yes |
| 0xE2 | TRX-2 | yes |
| 0xE3 | TRX-1 | yes |
| 0xE4 | PRO-668 | yes |
| 0xE5 | unknown | no |
| 0xE6 | WS1080/1088 | yes |
| 0xE7 | PRO-651/652 | no |
| 0xE8 | WS1040/1065 | no |
| 0xE9 | unknown | no |
| 0xEA | WS1095/1098 | yes |
| 0xEE | PSR-800 | no |

PRO-668 and WS1080/1088 share one key. `0xEE` is outside the 11-entry jump table, so it has no key.

## How the image is framed on the wire

The utility opens `\\.\COMn` at 115200 baud, 8 data bits, no parity. The image itself is not ASCII. Each chunk is hex-encoded with the table `0123456789ABCDEF` at file `0xA0188`, wrapped as STX (`0x02`) + hex + ETX (`0x03`) + a one-byte checksum, and written to the port. The header packet before the image is STX, the platform byte `0xE3`, the length as six uppercase hex digits (`0618AE`), ETX, and the checksum. `TRX1_CPU_U5.9.bin` is the payload after the RC4 layer, before that framing.

## What was ruled out

- The image is not in the PE resource directory. Resources there are icons, dialogs, and the version block.
- It is not AES. There is no AES S-box in the executable.
- It is not the older GRE repeating 512-byte CRC-table XOR by itself. A CRC-16-CCITT table is not present, and XORing either the stored bytes or the RC4 output with a generated CRC-16 table (plain repeat, block counter, or a running CRC keystream) does not produce a version byte of `0x59`, a readable version string, or a matching CRC-16.
- RC4 with the other five static keys, with and without the salt XOR, and with drop counts 0, 256, and 512, stays at ciphertext entropy.

## IDA

Launch `idat.exe` from `C:\Program Files\IDA Professional 9.1` through a Python argument list. Do not pass `-S` through a PowerShell command line. One `idat` at a time. The script used for the decompile is `ida\scripts\decompile.py`. The IDA database is not in the repository.
