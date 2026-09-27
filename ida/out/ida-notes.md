# CPUUpdater_TRX1_U5.9 cipher (IDA 9.1 Hex-Rays)

Database: `ida\db\CPUUpdater_TRX1_U5.9.i64` (not in the repository)
Image base `0x400000`. Header VA `0x41A618` / file `0x1A618`: platform `0xE3`, version `0x59`, u16 `0`, length `0x000618AE` (399534). Bit 31 is clear, so the send path ciphers. Payload VA `0x41A620`: 64-byte salt, then `0x618AE` ciphered bytes.

Hex-Rays agrees with the Capstone trace. No RC4 parameter change.

## sub_401490 key select

Hex-Rays constant-folds this file's platform byte and returns only the TRX-1 key:

```c
void *trx_key_select()
{
  return &trx1_key; /* 64 bytes, address omitted */
}
```

The real switch is still in the disassembly. Key addresses are omitted here. Index = `(byte)[0x41A618] + 0xFFFFFF20` = platform - `0xE0`, jump table VA `0x4014D4`, default NULL if index > 10.

| index | platform | key |
|---:|---:|:---|
| 0 | 0xE0 | yes |
| 1 | 0xE1 | yes |
| 2 | 0xE2 | yes |
| 3 | 0xE3 | yes |
| 4 | 0xE4 | yes |
| 5 | 0xE5 | NULL |
| 6 | 0xE6 | yes (same key as 0xE4) |
| 7 | 0xE7 | NULL |
| 8 | 0xE8 | NULL |
| 9 | 0xE9 | NULL |
| 10 | 0xEA | yes |

## sub_401500 RC4-drop256 setup

`trx_rc4_setup(state, static_key, 64, salt_copy)`

```c
int __cdecl trx_rc4_setup(int a1, int a2, int a3, _BYTE *a4)
{
  _BYTE *v4; int v5; int result; unsigned int i; char v8;
  unsigned int v9; char v10; int v11; int v12; int v13; int v14; char v15;

  if ( a3 > 0 )
  {
    v4 = a4;
    v5 = a3;
    do {
      *v4 ^= v4[a2 - (_DWORD)a4]; /* salt_copy[i] ^= static_key[i] */
      ++v4;
      --v5;
    } while ( v5 );
  }
  result = a1;
  for ( i = 0; i < 0x100; ++i )
    *(_BYTE *)(i + a1) = i;
  v8 = 0;
  v9 = 0;
  do {
    v10 = *(_BYTE *)(v9 + a1);
    v11 = (unsigned __int8)(v10 + v8 + a4[(a3 - 1) & v9++]);
    v8 = v11;
    *(_BYTE *)(v9 + a1 - 1) = *(_BYTE *)(v11 + a1);
    *(_BYTE *)(v11 + a1) = v10;
  } while ( v9 < 0x100 );
  LOBYTE(v12) = 0;
  LOBYTE(v13) = 0;
  v14 = 256;
  do {
    v13 = (unsigned __int8)(v13 + 1);
    v15 = *(_BYTE *)(v13 + a1);
    --v14;
    v12 = (unsigned __int8)(v12 + v15);
    *(_BYTE *)(v13 + a1) = *(_BYTE *)(v12 + a1);
    *(_BYTE *)(v12 + a1) = v15;
  } while ( v14 );
  *(_DWORD *)(a1 + 260) = v12; /* j */
  *(_DWORD *)(a1 + 256) = v13; /* i */
  return result;
}
```

## sub_4015B0 PRGA

```c
int __cdecl trx_rc4_prga(int a1, int a2, int a3)
{
  int result = a1;
  int v4 = *(_DWORD *)(a1 + 256); /* i */
  int v5 = 0;
  int v6 = *(_DWORD *)(a1 + 260); /* j */
  if ( a3 <= 0 ) {
    *(_DWORD *)(a1 + 260) = v6;
    *(_DWORD *)(a1 + 256) = v4;
  } else {
    do {
      v4 = (unsigned __int8)(v4 + 1);
      char v7 = *(_BYTE *)(v4 + a1);
      v6 = (unsigned __int8)(v7 + v6);
      char v8 = *(_BYTE *)(v6 + a1);
      *(_BYTE *)(v4 + a1) = v8;
      *(_BYTE *)(v6 + a1) = v7;
      *(_BYTE *)(a2 + v5++) ^= *(_BYTE *)((unsigned __int8)(v7 + v8) + a1);
    } while ( v5 < a3 );
    *(_DWORD *)(a1 + 260) = v6;
    *(_DWORD *)(a1 + 256) = v4;
  }
  return result;
}
```

## sub_402520 send (cipher part)

Hex-Rays folds this file's header: platform byte `0xE3` (`-29`), length `399534`, cipher flag on. State is a 264-byte stack buffer. Salt copy is 64 bytes at `[ebp-0x98]`.

```c
v66 = -29;                 /* platform 0xE3 */
v74 = 1;                   /* bit 31 of length was clear */
v62 = trx_key_select();    /* &trx1_key */
/* 10-byte hello: 0x02, platform, sprintf "%06X" of the low 24-bit length, 0x03, checksum */
if ( v62 && v74 ) {
  qmemcpy(v56, &unk_41A620, 64);
  trx_rc4_setup((int)v55, (int)v62, 64, v56);
  wParam = 64;             /* skip salt */
} else {
  wParam = 0;
}
lParam = 399534;           /* bytes to send */
if ( !wParam )
  lParam = 399598;         /* length + 64, salt included, cipher off */
for ( ; lParam; ) {
  v70 = min(64, lParam);
  lParam -= v70;
  qmemcpy(v56, (char *)&unk_41A620 + wParam, v70);
  wParam += v70;
  if ( v62 && v74 )
    trx_rc4_prga((int)v55, (int)v56, v70);
  /* hex-encode v56 with "0123456789ABCDEF" at 0x4A0188, frame 0x02 ... 0x03 + checksum, write COM */
}
```

## Algorithm

1. Key = 64-byte salt XOR the 64-byte TRX-1 static key. The XOR is on the stack copy.
2. RC4 KSA over that 64-byte key (`i & 63`).
3. Drop 256 PRGA bytes. `i` at `state+0x100`, `j` at `state+0x104`.
4. PRGA-XOR the next `0x618AE` payload bytes in 64-byte chunks. One continuous keystream. The salt is not transmitted.
5. On the wire those bytes are ASCII hex inside `02 <hex> 03 <sum>` frames. The recovered image is the post-RC4 bytes, before hex encoding.

`tools\extract_fw.py` matches Hex-Rays. Output sha256 `aaca739d8af603f841c2004e935e685860668ecc315cdb4e50a7ab17efd00632`.

## Second layer still closed

The post-RC4 image is not raw flash. Entropy 7.9975, chi-square 1365 (stored blob before RC4 is chi-square 259), 1415 zero bytes, no UTF-16 strings, no readable version text, byte 2 is `0x88` and byte 4 is `0x3F` (not `0x59`), CRC-16/CCITT of the remainder does not match the first u16. Not zlib, raw deflate, or lzma. No CRC-16 table and no AES S-box in the updater.

Ruled out on both the stored blob and the RC4 output: CRC-16 tables for polys `0x1021`, `0x8005`, `0x8408`, `0xA001` (both endians) as a 512-byte repeat, a block-counter lengthen, an `i>>8` / `i>>16` lengthen, a second table indexed by `i/512`, and 256-word mixes (`T[lo] ^ T[hi+adj]`, alternating bytes, index `lo+hi+adj`) for small adjustments including `0`, `0x59`, and `0xE3`. None yields a version byte `0x59` followed by a readable version string. The updater does not implement that older GRE XOR; it only RC4s what is already in the file. The inner obfuscation is not recovered here. No key was invented.
