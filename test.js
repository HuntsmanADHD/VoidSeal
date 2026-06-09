'use strict';
// One-shot status check: correctness (RFC vectors + Node native + BigInt oracle)
// and throughput. Run:  node test.js
const crypto = require('crypto');
const chacha = require('./chacha20.js');         // scalar reference
const chachaFast = require('./chacha20-fast.js'); // optimized pure JS
const polyRef = require('./poly1305.js');       // BigInt oracle
const polyFast = require('./poly1305-fast.js'); // limb version
const aead = require('./aead.js');

const hex = (b) => Buffer.from(b).toString('hex');
const rb = (n) => new Uint8Array(crypto.randomBytes(n));
let pass = 0, fail = 0;
const check = (name, ok) => { console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`); ok ? pass++ : fail++; };

console.log('ChaCha20-Poly1305  -  status check\n');

// ---------- ChaCha20 ----------
console.log('ChaCha20:');
{
  const key = new Uint8Array(32); for (let i = 0; i < 32; i++) key[i] = i;
  const nonce = Uint8Array.from([0,0,0,9, 0,0,0,0x4a, 0,0,0,0]);
  const ks = chacha.block(
    Uint32Array.from({ length: 8 }, (_, i) => (key[i*4] | key[i*4+1]<<8 | key[i*4+2]<<16 | key[i*4+3]<<24) >>> 0),
    1,
    [(nonce[0]|nonce[1]<<8|nonce[2]<<16|nonce[3]<<24)>>>0,(nonce[4]|nonce[5]<<8|nonce[6]<<16|nonce[7]<<24)>>>0,(nonce[8]|nonce[9]<<8|nonce[10]<<16|nonce[11]<<24)>>>0]);
  check('RFC 8439 2.3.2 keystream block', hex(ks) === '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e');
  let ok = true;
  for (const len of [0, 1, 63, 64, 65, 200, 1000, 4096]) {
    const k = rb(32), n = rb(12), p = rb(len), ctr = (Math.random()*1000)|0;
    const iv = Buffer.alloc(16); iv.writeUInt32LE(ctr, 0); Buffer.from(n).copy(iv, 4);
    const c = crypto.createCipheriv('chacha20', Buffer.from(k), iv);
    const nat = new Uint8Array(Buffer.concat([c.update(Buffer.from(p)), c.final()]));
    if (hex(chacha.chacha20(k, n, ctr, p)) !== hex(nat)) ok = false;
  }
  check('vs Node native chacha20 (8 random cases)', ok);
}

// ---------- ChaCha20 optimized (pure JS) ----------
console.log('\nChaCha20 (optimized pure JS):');
{
  let ok = true;
  for (let t = 0; t < 500; t++) {
    const len = t < 100 ? t : (Math.random()*9000|0);
    const k = rb(32), n = rb(12), p = rb(len), ctr = (Math.random()*1e6)|0;
    if (hex(chachaFast.chacha20(k, n, ctr, p)) !== hex(chacha.chacha20(k, n, ctr, p))) ok = false;
  }
  check('vs scalar reference (500 random, ctr varied)', ok);
}

// ---------- Poly1305 ----------
console.log('\nPoly1305 (limb):');
{
  const key = Buffer.from('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b', 'hex');
  check('RFC 8439 2.5.2 tag', hex(polyFast.poly1305(new Uint8Array(Buffer.from('Cryptographic Forum Research Group')), new Uint8Array(key))) === 'a8061dc1305136c6c22b8baf0c0127a9');
  let ok = true;
  for (let t = 0; t < 2000; t++) {
    const len = t < 200 ? t : (Math.random()*8200|0);
    const k = rb(32), m = rb(len);
    if (hex(polyFast.poly1305(m, k)) !== hex(polyRef.poly1305(m, k))) ok = false;
  }
  check('vs BigInt oracle (2000 random, lens 0-8200)', ok);
}

// ---------- AEAD ----------
console.log('\nChaCha20-Poly1305 AEAD:');
{
  // RFC 8439 2.8.2
  const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
  const nonce = Buffer.from('070000004041424344454647', 'hex');
  const ad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
  const pt = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const m = aead.seal(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(pt), new Uint8Array(ad));
  check('RFC 8439 2.8.2 tag', hex(m.tag) === '1ae10b594f09e26a7e902ecbd0600691');

  let ok = true, rt = true;
  for (const [a, p] of [[0,0],[0,1],[12,114],[0,64],[5,63],[17,1000],[64,4096]]) {
    const k = rb(32), n = rb(12), aad = rb(a), plain = rb(p);
    const c = crypto.createCipheriv('chacha20-poly1305', Buffer.from(k), Buffer.from(n), { authTagLength: 16 });
    c.setAAD(Buffer.from(aad));
    const nct = Buffer.concat([c.update(Buffer.from(plain)), c.final()]), ntag = c.getAuthTag();
    const mine = aead.seal(k, n, plain, aad);
    if (hex(mine.ciphertext) !== hex(nct) || hex(mine.tag) !== hex(ntag)) ok = false;
    const dec = aead.open(k, n, mine.ciphertext, mine.tag, aad);
    if (!dec || hex(dec) !== hex(plain)) rt = false;
  }
  check('vs Node native chacha20-poly1305 (7 cases)', ok);
  check('seal / open round-trip', rt);
  const k = rb(32), n = rb(12), p = rb(50);
  const m2 = aead.seal(k, n, p); m2.ciphertext[0] ^= 1;
  check('tamper rejected', aead.open(k, n, m2.ciphertext, m2.tag) === null);
}

// ---------- throughput ----------
console.log('\nThroughput (64 KiB):');
const k = rb(32), n = rb(12), data = new Uint8Array(65536);
const bench = (fn, it) => { for (let i = 0; i < 30; i++) fn(); const t = process.hrtime.bigint(); for (let i = 0; i < it; i++) fn(); return (65536 * it) / (Number(process.hrtime.bigint() - t) / 1e9) / 1048576; };
const fmt = (x) => x.toFixed(0).padStart(6) + ' MiB/s';
console.log('  this AEAD (pure JS, no WASM, no deps):' + fmt(bench(() => aead.seal(k, n, data), 1000)));
console.log('  Node native (OpenSSL):                ' + fmt(bench(() => { const c = crypto.createCipheriv('chacha20-poly1305', Buffer.from(k), Buffer.from(n), { authTagLength: 16 }); c.update(Buffer.from(data)); c.final(); c.getAuthTag(); }, 3000)));
console.log('  Poly1305 limb (MAC only):             ' + fmt(bench(() => polyFast.poly1305(data, k), 2000)));

console.log(`\n${fail === 0 ? 'ALL ' + pass + ' CHECKS PASS' : fail + ' FAILURES'}  -  100% pure JavaScript, zero dependencies, no shipped binary.`);
process.exit(fail ? 1 : 0);
