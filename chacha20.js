'use strict';
// ChaCha20 stream cipher (RFC 8439) - clean scalar reference.
// This is the verification baseline; the WASM-SIMD build will be checked against
// it and against Node's native OpenSSL chacha20.

const CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // "expand 32-byte k"

function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

// ChaCha quarter-round (the ARX primitive - same family as BLAKE3's G, left-rotations)
function qr(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
}

function le32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

// One 64-byte keystream block for (key, blockCounter, nonce).
function block(keyWords, counter, nonceWords) {
  const s = new Uint32Array(16);
  s[0] = CONSTANTS[0]; s[1] = CONSTANTS[1]; s[2] = CONSTANTS[2]; s[3] = CONSTANTS[3];
  for (let i = 0; i < 8; i++) s[4 + i] = keyWords[i];
  s[12] = counter >>> 0;
  s[13] = nonceWords[0]; s[14] = nonceWords[1]; s[15] = nonceWords[2];

  const w = s.slice();
  for (let i = 0; i < 10; i++) {           // 20 rounds = 10 column/diagonal double-rounds
    qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
    qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
  }
  for (let i = 0; i < 16; i++) w[i] = (w[i] + s[i]) >>> 0; // feed-forward add

  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const x = w[i];
    out[i * 4] = x & 255; out[i * 4 + 1] = (x >>> 8) & 255; out[i * 4 + 2] = (x >>> 16) & 255; out[i * 4 + 3] = (x >>> 24) & 255;
  }
  return out;
}

// Encrypt/decrypt (XOR with keystream). key: 32 bytes, nonce: 12 bytes, counter: start block.
function chacha20(key, nonce, counter, data) {
  const keyWords = new Uint32Array(8);
  for (let i = 0; i < 8; i++) keyWords[i] = le32(key, i * 4);
  const nonceWords = [le32(nonce, 0), le32(nonce, 4), le32(nonce, 8)];

  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 64) {
    const ks = block(keyWords, (counter + (off >> 6)) >>> 0, nonceWords);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}

function toHex(b) { let s = ''; for (const x of b) s += (x < 16 ? '0' : '') + x.toString(16); return s; }

module.exports = { chacha20, block, qr, toHex };
