'use strict';
// Poly1305 - 4-way parallel (powers of r), the vectorization SIMD is built on.
// Poly1305 is sequential: h = (h + m)*r per block. Splitting blocks across 4
// independent accumulator lanes (each advancing by r^4) breaks that dependency
// chain, then a final combine folds the lanes with r^4, r^3, r^2, r.
// 10 x 13-bit limbs (exact in doubles). Verified vs the BigInt oracle.

const P = (1n << 130n) - 5n;
const MASK128 = (1n << 128n) - 1n;

// out = (a * r) mod (2^130 - 5)   (a,r: 10 limbs; s = 5*r limbs 1..9; out: 10 limbs)
function mul(a, r, s, out) {
  const h0=a[0],h1=a[1],h2=a[2],h3=a[3],h4=a[4],h5=a[5],h6=a[6],h7=a[7],h8=a[8],h9=a[9];
  const r0=r[0],r1=r[1],r2=r[2],r3=r[3],r4=r[4],r5=r[5],r6=r[6],r7=r[7],r8=r[8],r9=r[9];
  const s1=s[1],s2=s[2],s3=s[3],s4=s[4],s5=s[5],s6=s[6],s7=s[7],s8=s[8],s9=s[9];
  let d0=h0*r0+h1*s9+h2*s8+h3*s7+h4*s6+h5*s5+h6*s4+h7*s3+h8*s2+h9*s1;
  let d1=h0*r1+h1*r0+h2*s9+h3*s8+h4*s7+h5*s6+h6*s5+h7*s4+h8*s3+h9*s2;
  let d2=h0*r2+h1*r1+h2*r0+h3*s9+h4*s8+h5*s7+h6*s6+h7*s5+h8*s4+h9*s3;
  let d3=h0*r3+h1*r2+h2*r1+h3*r0+h4*s9+h5*s8+h6*s7+h7*s6+h8*s5+h9*s4;
  let d4=h0*r4+h1*r3+h2*r2+h3*r1+h4*r0+h5*s9+h6*s8+h7*s7+h8*s6+h9*s5;
  let d5=h0*r5+h1*r4+h2*r3+h3*r2+h4*r1+h5*r0+h6*s9+h7*s8+h8*s7+h9*s6;
  let d6=h0*r6+h1*r5+h2*r4+h3*r3+h4*r2+h5*r1+h6*r0+h7*s9+h8*s8+h9*s7;
  let d7=h0*r7+h1*r6+h2*r5+h3*r4+h4*r3+h5*r2+h6*r1+h7*r0+h8*s9+h9*s8;
  let d8=h0*r8+h1*r7+h2*r6+h3*r5+h4*r4+h5*r3+h6*r2+h7*r1+h8*r0+h9*s9;
  let d9=h0*r9+h1*r8+h2*r7+h3*r6+h4*r5+h5*r4+h6*r3+h7*r2+h8*r1+h9*r0;
  let c;
  c=Math.floor(d0/8192);out[0]=d0-c*8192;d1+=c;
  c=Math.floor(d1/8192);out[1]=d1-c*8192;d2+=c;
  c=Math.floor(d2/8192);out[2]=d2-c*8192;d3+=c;
  c=Math.floor(d3/8192);out[3]=d3-c*8192;d4+=c;
  c=Math.floor(d4/8192);out[4]=d4-c*8192;d5+=c;
  c=Math.floor(d5/8192);out[5]=d5-c*8192;d6+=c;
  c=Math.floor(d6/8192);out[6]=d6-c*8192;d7+=c;
  c=Math.floor(d7/8192);out[7]=d7-c*8192;d8+=c;
  c=Math.floor(d8/8192);out[8]=d8-c*8192;d9+=c;
  c=Math.floor(d9/8192);out[9]=d9-c*8192;
  out[0]+=c*5;c=Math.floor(out[0]/8192);out[0]-=c*8192;out[1]+=c;
}
const mk5 = (r) => { const s = new Float64Array(10); for (let i = 1; i < 10; i++) s[i] = 5 * r[i]; return s; };

// load 13-bit limbs from a 16-byte block (+ hibit) into `lm`
function loadBlock(m, mo, hibit, lm) {
  const t0=m[mo]|(m[mo+1]<<8),t1=m[mo+2]|(m[mo+3]<<8),t2=m[mo+4]|(m[mo+5]<<8),t3=m[mo+6]|(m[mo+7]<<8);
  const t4=m[mo+8]|(m[mo+9]<<8),t5=m[mo+10]|(m[mo+11]<<8),t6=m[mo+12]|(m[mo+13]<<8),t7=m[mo+14]|(m[mo+15]<<8);
  lm[0]=t0&0x1fff; lm[1]=((t0>>>13)|(t1<<3))&0x1fff; lm[2]=((t1>>>10)|(t2<<6))&0x1fff; lm[3]=((t2>>>7)|(t3<<9))&0x1fff;
  lm[4]=((t3>>>4)|(t4<<12))&0x1fff; lm[5]=(t4>>>1)&0x1fff; lm[6]=((t4>>>14)|(t5<<2))&0x1fff; lm[7]=((t5>>>11)|(t6<<5))&0x1fff;
  lm[8]=((t6>>>8)|(t7<<8))&0x1fff; lm[9]=(t7>>>5)+hibit;
}

// preallocated scratch (one-shot, single-threaded)
const r1 = new Float64Array(10), r2 = new Float64Array(10), r3 = new Float64Array(10), r4 = new Float64Array(10);
const a0 = new Float64Array(10), a1 = new Float64Array(10), a2 = new Float64Array(10), a3 = new Float64Array(10);
const tmp = new Float64Array(10), lm = new Float64Array(10), acc = new Float64Array(10), buf = new Uint8Array(16);

function poly1305(msg, key) {
  // clamp r -> 10 limbs
  for (let i = 0; i < 16; i++) buf[i] = key[i];
  buf[3]&=15;buf[7]&=15;buf[11]&=15;buf[15]&=15;buf[4]&=252;buf[8]&=252;buf[12]&=252;
  loadBlock(buf, 0, 0, r1);
  const s1 = mk5(r1);
  mul(r1, r1, s1, r2); const s2 = mk5(r2);   // r^2
  mul(r2, r1, s1, r3); const s3 = mk5(r3);   // r^3
  mul(r2, r2, s2, r4); const s4 = mk5(r4);   // r^4

  for (let i = 0; i < 10; i++) { a0[i]=0; a1[i]=0; a2[i]=0; a3[i]=0; }

  const nFull = msg.length >> 6 << 2;        // number of 16-byte blocks in full 4-groups... (see below)
  const nBlocks = Math.floor(msg.length / 16);
  const groups = nBlocks >> 2;               // full groups of 4 blocks
  let off = 0;

  // 4-way parallel over full groups: a_j = a_j*r4 + m_j
  for (let g = 0; g < groups; g++) {
    mul(a0, r4, s4, a0); loadBlock(msg, off,      0x800, lm); for (let i=0;i<10;i++) a0[i]+=lm[i];
    mul(a1, r4, s4, a1); loadBlock(msg, off + 16, 0x800, lm); for (let i=0;i<10;i++) a1[i]+=lm[i];
    mul(a2, r4, s4, a2); loadBlock(msg, off + 32, 0x800, lm); for (let i=0;i<10;i++) a2[i]+=lm[i];
    mul(a3, r4, s4, a3); loadBlock(msg, off + 48, 0x800, lm); for (let i=0;i<10;i++) a3[i]+=lm[i];
    off += 64;
  }

  // combine lanes: H = a0*r4 + a1*r3 + a2*r2 + a3*r
  for (let i = 0; i < 10; i++) acc[i] = 0;
  mul(a0, r4, s4, tmp); for (let i=0;i<10;i++) acc[i]+=tmp[i];
  mul(a1, r3, s3, tmp); for (let i=0;i<10;i++) acc[i]+=tmp[i];
  mul(a2, r2, s2, tmp); for (let i=0;i<10;i++) acc[i]+=tmp[i];
  mul(a3, r1, s1, tmp); for (let i=0;i<10;i++) acc[i]+=tmp[i];
  { let c=0; for (let i=0;i<10;i++){ acc[i]+=c; c=Math.floor(acc[i]/8192); acc[i]-=c*8192; } acc[0]+=c*5; c=Math.floor(acc[0]/8192); acc[0]-=c*8192; acc[1]+=c; }

  // remaining blocks (< 4) sequentially: H = (H + m) * r
  while (off + 16 <= msg.length) { loadBlock(msg, off, 0x800, lm); for (let i=0;i<10;i++) acc[i]+=lm[i]; mul(acc, r1, s1, acc); off += 16; }
  if (off < msg.length) { buf.fill(0); let i=0; for (; off+i<msg.length; i++) buf[i]=msg[off+i]; buf[i]=1; loadBlock(buf,0,0,lm); for (let k=0;k<10;k++) acc[k]+=lm[k]; mul(acc, r1, s1, acc); off = msg.length; }

  // final: (H mod p + s) mod 2^128
  let hn = 0n; for (let i = 0; i < 10; i++) hn += BigInt(acc[i]) << BigInt(13 * i);
  hn %= P;
  let sN = 0n; for (let i = 31; i >= 16; i--) sN = (sN << 8n) | BigInt(key[i]);
  hn = (hn + sN) & MASK128;
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) { tag[i] = Number(hn & 0xffn); hn >>= 8n; }
  return tag;
}

function toHex(b) { let s = ''; for (const x of b) s += (x < 16 ? '0' : '') + x.toString(16); return s; }
module.exports = { poly1305, toHex };
