'use strict';
// Poly1305 one-time authenticator (RFC 8439 section 2.5) - BigInt reference.
// Exact field arithmetic mod p = 2^130 - 5. This is the correctness baseline;
// the WASM-SIMD build will use 26-bit limb arithmetic and be checked against it.

const P = (1n << 130n) - 5n;
const MASK128 = (1n << 128n) - 1n;
const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

function leBytesToBigInt(bytes, off, len) {
  let n = 0n;
  for (let i = len - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[off + i]);
  return n;
}

// msg: Uint8Array, key: 32 bytes (r||s). Returns 16-byte tag.
function poly1305(msg, key) {
  const r = leBytesToBigInt(key, 0, 16) & CLAMP; // clamp r
  const s = leBytesToBigInt(key, 16, 16);
  let acc = 0n;

  for (let off = 0; off < msg.length; off += 16) {
    const n = Math.min(16, msg.length - off);
    // block = the bytes as LE integer, with a 1 bit appended above the top byte
    const block = leBytesToBigInt(msg, off, n) + (1n << BigInt(8 * n));
    acc = ((acc + block) * r) % P;
  }

  acc = (acc + s) & MASK128;
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) { tag[i] = Number(acc & 0xffn); acc >>= 8n; }
  return tag;
}

function toHex(b) { let s = ''; for (const x of b) s += (x < 16 ? '0' : '') + x.toString(16); return s; }

module.exports = { poly1305, toHex };
