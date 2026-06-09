'use strict';
// ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8) - 100% pure JavaScript.
// Composes the optimized pure-JS ChaCha20 + limb Poly1305. No WebAssembly, no
// dependencies. Checked against Node's native OpenSSL and the RFC test vectors.

const { chacha20 } = require('./chacha20-fast.js');
const { poly1305 } = require('./poly1305-fast.js');

// Poly1305 one-time key = first 32 bytes of the ChaCha20 counter-0 block.
function poly1305KeyGen(key, nonce) {
  return chacha20(key, nonce, 0, new Uint8Array(32));
}

const pad16 = (len) => (16 - (len % 16)) % 16;

function writeLE64(buf, off, value) {
  const lo = value >>> 0, hi = Math.floor(value / 0x100000000) >>> 0;
  buf[off] = lo & 255; buf[off + 1] = (lo >>> 8) & 255; buf[off + 2] = (lo >>> 16) & 255; buf[off + 3] = (lo >>> 24) & 255;
  buf[off + 4] = hi & 255; buf[off + 5] = (hi >>> 8) & 255; buf[off + 6] = (hi >>> 16) & 255; buf[off + 7] = (hi >>> 24) & 255;
}

// Build the Poly1305 input: aad || pad16 || ciphertext || pad16 || le64(aadLen) || le64(ctLen)
function macData(aad, ct) {
  const len = aad.length + pad16(aad.length) + ct.length + pad16(ct.length) + 16;
  const d = new Uint8Array(len);
  let o = 0;
  d.set(aad, o); o += aad.length + pad16(aad.length);
  d.set(ct, o); o += ct.length + pad16(ct.length);
  writeLE64(d, o, aad.length); o += 8;
  writeLE64(d, o, ct.length);
  return d;
}

function seal(key, nonce, plaintext, aad = new Uint8Array(0)) {
  const otk = poly1305KeyGen(key, nonce);
  const ct = chacha20(key, nonce, 1, plaintext);
  const tag = poly1305(macData(aad, ct), otk);
  return { ciphertext: ct, tag };
}

// constant-time tag compare
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function open(key, nonce, ciphertext, tag, aad = new Uint8Array(0)) {
  const otk = poly1305KeyGen(key, nonce);
  const expect = poly1305(macData(aad, ciphertext), otk);
  if (!ctEqual(expect, tag)) return null; // authentication failed
  return chacha20(key, nonce, 1, ciphertext);
}

function toHex(b) { let s = ''; for (const x of b) s += (x < 16 ? '0' : '') + x.toString(16); return s; }

module.exports = { seal, open, poly1305KeyGen, toHex };
