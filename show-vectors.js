'use strict';
// Prints the shipped voidseal.js output next to the official RFC 8439 values.
const V = require('./voidseal.js');

const H = (b) => Buffer.from(b).toString('hex');
const rows = (h) => h.match(/.{1,32}/g).map(r => '    ' + (r.match(/.{1,2}/g).join(' '))).join('\n');
function show(label, got, expected) {
  const ok = got === expected;
  console.log(label);
  console.log('  ours:\n' + rows(got));
  console.log('  RFC :\n' + rows(expected));
  console.log('  => ' + (ok ? 'MATCH ✓' : 'MISMATCH ✗') + '\n');
  return ok;
}

let all = true;
console.log('='.repeat(54) + '\n RFC 8439 test vectors: ours vs the official answer\n' + '='.repeat(54) + '\n');

// ---- ChaCha20 keystream block (RFC 2.3.2) ----
{
  const key = new Uint8Array(32); for (let i = 0; i < 32; i++) key[i] = i;
  const nonce = Uint8Array.from([0,0,0,9, 0,0,0,0x4a, 0,0,0,0]);
  const ks = V.chacha20(key, nonce, 1, new Uint8Array(64)); // keystream = encrypt zeros
  console.log('--- ChaCha20 keystream block (key 00..1f, counter 1) ---');
  all &= show('64-byte keystream block:', H(ks),
    '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e');
}

// ---- Poly1305 tag (RFC 2.5.2) ----
{
  const key = Buffer.from('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b', 'hex');
  const msg = Buffer.from('Cryptographic Forum Research Group');
  console.log('--- Poly1305 tag (message "Cryptographic Forum Research Group") ---');
  all &= show('16-byte tag:', H(V.poly1305(new Uint8Array(msg), new Uint8Array(key))), 'a8061dc1305136c6c22b8baf0c0127a9');
}

// ---- Full AEAD (RFC 2.8.2) ----
{
  const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
  const nonce = Buffer.from('070000004041424344454647', 'hex');
  const ad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
  const pt = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const { ciphertext, tag } = V.seal(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(pt), new Uint8Array(ad));
  console.log('--- ChaCha20-Poly1305 AEAD (the sunscreen speech) ---');
  console.log('  plaintext: "' + pt.toString() + '"\n');
  all &= show('ciphertext (114 bytes):', H(ciphertext),
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116');
  all &= show('auth tag (16 bytes):', H(tag), '1ae10b594f09e26a7e902ecbd0600691');
}

console.log('='.repeat(54));
console.log(all ? ' Every byte matches the RFC. ✓' : ' MISMATCH found. ✗');
console.log('='.repeat(54));
