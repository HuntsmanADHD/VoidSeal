# ChaCha20-Poly1305 (pure JavaScript)

A from-scratch, RFC 8439-conformant **ChaCha20-Poly1305** authenticated cipher —
the standard "encrypt + tamper-proof" AEAD used in TLS, WireGuard, and modern
messengers — written in **100% pure JavaScript**.

> **No WebAssembly. No native bindings. No dependencies. No shipped or generated
> binary.** Every byte that runs is JavaScript you can read. It runs anywhere JS
> runs, and there's nothing in the supply chain to trust but the source in front
> of you.

## What it does

- **ChaCha20** scrambles the message (confidentiality).
- **Poly1305** stamps a one-time tag proving it wasn't altered (integrity).
- Together: hidden *and* tamper-evident — "authenticated encryption."

## Verified correct

Checked against **both** ground truths:
- the official **RFC 8439 test vectors** (byte-for-byte — see `show-vectors.js`), and
- **Node's native OpenSSL** `chacha20-poly1305`, over thousands of random inputs.

Matches exactly, every time — plus `seal`/`open` round-trip and tamper-rejection.

## Speed (this machine, 64 KiB, single thread)

| version | throughput |
|---|---|
| pre-optimized (reference + BigInt) | ~32 MiB/s |
| **optimized pure JS (this)** | **~150-180 MiB/s** |
| tweetnacl (for comparison) | ~40-80 MiB/s |
| Node native OpenSSL (native code) | ~2000 MiB/s |

~5x faster than the naive start, and ~2-4x faster than `tweetnacl` — while staying
pure, auditable, and dependency-free.

## Files

| file | what |
|---|---|
| `aead.js` | the full AEAD: `seal()` / `open()` |
| `chacha20-fast.js` | optimized pure-JS ChaCha20 (fully unrolled, zero-alloc) — the cipher |
| `chacha20.js` | scalar ChaCha20 reference |
| `poly1305-fast.js` | Poly1305 via 13-bit limb math — the MAC |
| `poly1305-simd.js` | 4-way parallel Poly1305 (reference / future vectorization base) |
| `poly1305.js` | exact BigInt Poly1305 (the correctness oracle) |
| `test.js` | one-command verification + benchmark |
| `show-vectors.js` | prints our output next to the official RFC answer, byte for byte |

## See for yourself

```
node test.js           # 9/9 checks: RFC vectors + match vs Node native + tamper test
node show-vectors.js   # actual output vs the official RFC answer, side by side
```

`node test.js` ends with **`ALL 9 CHECKS PASS`** when everything is correct.

## Use it

```js
const { seal, open } = require('./aead.js');
const { ciphertext, tag } = seal(key32, nonce12, plaintext, aad);  // encrypt + authenticate
const plaintext = open(key32, nonce12, ciphertext, tag, aad);       // null if tampered
```

## Honest note

Native OpenSSL is ~10x faster because it runs compiled machine code with wide
(AVX) SIMD — things JavaScript can't express. This trades that raw speed for being
**pure, dependency-free, and binary-free**: nothing hidden, nothing to compile,
nothing to trust but the source.
