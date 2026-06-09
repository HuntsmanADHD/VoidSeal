'use strict';
// VoidSeal status check: verifies the shipped file (voidseal.js) against the
// official RFC 8439 test vectors AND Node's native OpenSSL across random inputs.
// No extra files needed - the RFC answer key and OpenSSL are the ground truths.
// Run:  node test.js
const crypto = require('crypto');
const V = require('./voidseal.js');

const hex = (b) => Buffer.from(b).toString('hex');
const rb = (n) => new Uint8Array(crypto.randomBytes(n));
let pass = 0, fail = 0;
const check = (name, ok) => { console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`); ok ? pass++ : fail++; };

console.log('VoidSeal (ChaCha20-Poly1305)  -  status check\n');

// ---------- ChaCha20 ----------
console.log('ChaCha20:');
{
  const key = new Uint8Array(32); for (let i = 0; i < 32; i++) key[i] = i;
  const nonce = Uint8Array.from([0,0,0,9, 0,0,0,0x4a, 0,0,0,0]);
  const ks = V.chacha20(key, nonce, 1, new Uint8Array(64)); // keystream = encrypt zeros at counter 1
  check('RFC 8439 2.3.2 keystream block', hex(ks) === '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e');
  let ok = true;
  for (let t = 0; t < 500; t++) {
    const len = t < 100 ? t : (Math.random()*9000|0);
    const k = rb(32), n = rb(12), p = rb(len), ctr = (Math.random()*1e6)|0;
    const iv = Buffer.alloc(16); iv.writeUInt32LE(ctr, 0); Buffer.from(n).copy(iv, 4);
    const c = crypto.createCipheriv('chacha20', Buffer.from(k), iv);
    const nat = new Uint8Array(Buffer.concat([c.update(Buffer.from(p)), c.final()]));
    if (hex(V.chacha20(k, n, ctr, p)) !== hex(nat)) ok = false;
  }
  check('vs Node native chacha20 (500 random inputs)', ok);
}

// ---------- Poly1305 ----------
console.log('\nPoly1305:');
{
  const key = Buffer.from('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b', 'hex');
  check('RFC 8439 2.5.2 tag', hex(V.poly1305(new Uint8Array(Buffer.from('Cryptographic Forum Research Group')), new Uint8Array(key))) === 'a8061dc1305136c6c22b8baf0c0127a9');
  // (Poly1305 is also exercised on thousands of random inputs via the AEAD-vs-native check below)
}

// ---------- ChaCha20-Poly1305 AEAD ----------
console.log('\nChaCha20-Poly1305 AEAD:');
{
  // RFC 8439 2.8.2
  const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
  const nonce = Buffer.from('070000004041424344454647', 'hex');
  const ad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
  const pt = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const m = V.seal(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(pt), new Uint8Array(ad));
  check('RFC 8439 2.8.2 tag', hex(m.tag) === '1ae10b594f09e26a7e902ecbd0600691');

  // 200 random inputs vs Node native (exercises ChaCha *and* Poly1305 together against OpenSSL)
  let ok = true, rt = true;
  for (let t = 0; t < 200; t++) {
    const k = rb(32), n = rb(12), aad = rb((Math.random()*64)|0), plain = rb((Math.random()*5000)|0);
    const c = crypto.createCipheriv('chacha20-poly1305', Buffer.from(k), Buffer.from(n), { authTagLength: 16 });
    c.setAAD(Buffer.from(aad));
    const nct = Buffer.concat([c.update(Buffer.from(plain)), c.final()]), ntag = c.getAuthTag();
    const mine = V.seal(k, n, plain, aad);
    if (hex(mine.ciphertext) !== hex(nct) || hex(mine.tag) !== hex(ntag)) ok = false;
    const dec = V.open(k, n, mine.ciphertext, mine.tag, aad);
    if (!dec || hex(dec) !== hex(plain)) rt = false;
  }
  check('vs Node native chacha20-poly1305 (200 random inputs)', ok);
  check('seal / open round-trip (200 inputs)', rt);
  const k = rb(32), n = rb(12), p = rb(50);
  const m2 = V.seal(k, n, p); m2.ciphertext[0] ^= 1;
  check('tamper rejected', V.open(k, n, m2.ciphertext, m2.tag) === null);
}

// ---------- throughput ----------
console.log('\nThroughput (64 KiB):');
const k = rb(32), n = rb(12), data = new Uint8Array(65536);
const bench = (fn, it) => { for (let i = 0; i < 30; i++) fn(); const t = process.hrtime.bigint(); for (let i = 0; i < it; i++) fn(); return (65536 * it) / (Number(process.hrtime.bigint() - t) / 1e9) / 1048576; };
const fmt = (x) => x.toFixed(0).padStart(6) + ' MiB/s';
console.log('  VoidSeal (pure JS, no WASM, no deps): ' + fmt(bench(() => V.seal(k, n, data), 1000)));
console.log('  Node native (OpenSSL):                ' + fmt(bench(() => { const c = crypto.createCipheriv('chacha20-poly1305', Buffer.from(k), Buffer.from(n), { authTagLength: 16 }); c.update(Buffer.from(data)); c.final(); c.getAuthTag(); }, 3000)));

console.log(`\n${fail === 0 ? 'ALL ' + pass + ' CHECKS PASS' : fail + ' FAILURES'}  -  one file, 100% pure JavaScript, zero dependencies.`);
process.exit(fail ? 1 : 0);
