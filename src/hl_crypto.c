/*
 * purple-hotline: SHA-256, SHA-1, HMAC, HKDF and ChaCha20-Poly1305 in portable C.
 * See hl_crypto.h. Copyright (c) 2026 John Leighow. MIT license.
 */
#include "hl_crypto.h"

#include <stdio.h>
#include <string.h>

typedef unsigned long long hl_u64;

#define ROTL(x, n) ((hl_u32)(((x) << (n)) | ((x) >> (32 - (n)))))
#define ROTR(x, n) ((hl_u32)(((x) >> (n)) | ((x) << (32 - (n)))))

static hl_u32 be32(const hl_u8 *p)
{
	return ((hl_u32)p[0] << 24) | ((hl_u32)p[1] << 16) | ((hl_u32)p[2] << 8) | (hl_u32)p[3];
}

static void put_be32(hl_u8 *p, hl_u32 v)
{
	p[0] = (hl_u8)(v >> 24); p[1] = (hl_u8)(v >> 16); p[2] = (hl_u8)(v >> 8); p[3] = (hl_u8)v;
}

static hl_u32 le32(const hl_u8 *p)
{
	return (hl_u32)p[0] | ((hl_u32)p[1] << 8) | ((hl_u32)p[2] << 16) | ((hl_u32)p[3] << 24);
}

static void put_le32(hl_u8 *p, hl_u32 v)
{
	p[0] = (hl_u8)v; p[1] = (hl_u8)(v >> 8); p[2] = (hl_u8)(v >> 16); p[3] = (hl_u8)(v >> 24);
}

static void add_len(hl_u32 *hi, hl_u32 *lo, size_t n)
{
	hl_u32 before = *lo;
	*lo += (hl_u32)n;
	if (*lo < before)
		(*hi)++;
}

/* Both hashes end the same way: 0x80, zeros, the length in bits, big-endian. */
static void pad_be(hl_u8 *buf, hl_u32 *used, hl_u32 len_hi, hl_u32 len_lo,
                   void (*block)(void *, const hl_u8 *), void *ctx)
{
	hl_u32 bits_hi = (len_hi << 3) | (len_lo >> 29), bits_lo = len_lo << 3;
	buf[(*used)++] = 0x80;
	if (*used > 56) {
		memset(buf + *used, 0, 64 - *used);
		block(ctx, buf);
		*used = 0;
	}
	memset(buf + *used, 0, 56 - *used);
	put_be32(buf + 56, bits_hi);
	put_be32(buf + 60, bits_lo);
	block(ctx, buf);
}

/* ---------- SHA-256 ---------- */

static const hl_u32 K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_block(void *vc, const hl_u8 *p)
{
	hl_sha256_ctx *c = (hl_sha256_ctx *)vc;
	hl_u32 w[64], a, b, cc, d, e, f, g, h, t1, t2;
	int i;
	for (i = 0; i < 16; i++)
		w[i] = be32(p + 4 * i);
	for (i = 16; i < 64; i++) {
		hl_u32 s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		hl_u32 s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (i = 0; i < 64; i++) {
		t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
		t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

void hl_sha256_init(hl_sha256_ctx *c)
{
	static const hl_u32 iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	memcpy(c->h, iv, sizeof iv);
	c->used = 0;
	c->len_hi = c->len_lo = 0;
}

void hl_sha256_update(hl_sha256_ctx *c, const hl_u8 *p, size_t n)
{
	add_len(&c->len_hi, &c->len_lo, n);
	while (n > 0) {
		size_t take = 64 - c->used;
		if (take > n)
			take = n;
		memcpy(c->buf + c->used, p, take);
		c->used += (hl_u32)take;
		p += take;
		n -= take;
		if (c->used == 64) {
			sha256_block(c, c->buf);
			c->used = 0;
		}
	}
}

void hl_sha256_final(hl_sha256_ctx *c, hl_u8 out[HL_SHA256_LEN])
{
	int i;
	pad_be(c->buf, &c->used, c->len_hi, c->len_lo, sha256_block, c);
	for (i = 0; i < 8; i++)
		put_be32(out + 4 * i, c->h[i]);
}

/* ---------- SHA-1 ---------- */

static void sha1_block(void *vc, const hl_u8 *p)
{
	hl_sha1_ctx *c = (hl_sha1_ctx *)vc;
	hl_u32 w[80], a, b, cc, d, e, t;
	int i;
	for (i = 0; i < 16; i++)
		w[i] = be32(p + 4 * i);
	for (i = 16; i < 80; i++)
		w[i] = ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];
	for (i = 0; i < 80; i++) {
		hl_u32 f, k;
		if (i < 20) { f = (b & cc) | (~b & d); k = 0x5a827999; }
		else if (i < 40) { f = b ^ cc ^ d; k = 0x6ed9eba1; }
		else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8f1bbcdc; }
		else { f = b ^ cc ^ d; k = 0xca62c1d6; }
		t = ROTL(a, 5) + f + e + k + w[i];
		e = d; d = cc; cc = ROTL(b, 30); b = a; a = t;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

void hl_sha1_init(hl_sha1_ctx *c)
{
	c->h[0] = 0x67452301; c->h[1] = 0xefcdab89; c->h[2] = 0x98badcfe;
	c->h[3] = 0x10325476; c->h[4] = 0xc3d2e1f0;
	c->used = 0;
	c->len_hi = c->len_lo = 0;
}

void hl_sha1_update(hl_sha1_ctx *c, const hl_u8 *p, size_t n)
{
	add_len(&c->len_hi, &c->len_lo, n);
	while (n > 0) {
		size_t take = 64 - c->used;
		if (take > n)
			take = n;
		memcpy(c->buf + c->used, p, take);
		c->used += (hl_u32)take;
		p += take;
		n -= take;
		if (c->used == 64) {
			sha1_block(c, c->buf);
			c->used = 0;
		}
	}
}

void hl_sha1_final(hl_sha1_ctx *c, hl_u8 out[HL_SHA1_LEN])
{
	int i;
	pad_be(c->buf, &c->used, c->len_hi, c->len_lo, sha1_block, c);
	for (i = 0; i < 5; i++)
		put_be32(out + 4 * i, c->h[i]);
}

/* ---------- HMAC and HKDF ---------- */

void hl_hmac_sha256(const hl_u8 *key, size_t klen, const hl_u8 *msg, size_t mlen, hl_u8 out[HL_SHA256_LEN])
{
	hl_u8 k[64], pad[64], inner[HL_SHA256_LEN];
	hl_sha256_ctx c;
	int i;
	memset(k, 0, sizeof k);
	if (klen > 64) {
		hl_sha256_init(&c);
		hl_sha256_update(&c, key, klen);
		hl_sha256_final(&c, k);
	} else if (klen > 0) {
		memcpy(k, key, klen);
	}
	for (i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x36;
	hl_sha256_init(&c);
	hl_sha256_update(&c, pad, 64);
	hl_sha256_update(&c, msg, mlen);
	hl_sha256_final(&c, inner);
	for (i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x5c;
	hl_sha256_init(&c);
	hl_sha256_update(&c, pad, 64);
	hl_sha256_update(&c, inner, sizeof inner);
	hl_sha256_final(&c, out);
}

void hl_hmac_sha1(const hl_u8 *key, size_t klen, const hl_u8 *msg, size_t mlen, hl_u8 out[HL_SHA1_LEN])
{
	hl_u8 k[64], pad[64], inner[HL_SHA1_LEN];
	hl_sha1_ctx c;
	int i;
	memset(k, 0, sizeof k);
	if (klen > 64) {
		hl_sha1_init(&c);
		hl_sha1_update(&c, key, klen);
		hl_sha1_final(&c, k);
	} else if (klen > 0) {
		memcpy(k, key, klen);
	}
	for (i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x36;
	hl_sha1_init(&c);
	hl_sha1_update(&c, pad, 64);
	hl_sha1_update(&c, msg, mlen);
	hl_sha1_final(&c, inner);
	for (i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x5c;
	hl_sha1_init(&c);
	hl_sha1_update(&c, pad, 64);
	hl_sha1_update(&c, inner, sizeof inner);
	hl_sha1_final(&c, out);
}

void hl_hkdf_sha256(const hl_u8 *ikm, size_t ilen, const hl_u8 *salt, size_t slen,
                    const hl_u8 *info, size_t nlen, hl_u8 *out, size_t olen)
{
	hl_u8 prk[HL_SHA256_LEN], t[HL_SHA256_LEN], block[HL_SHA256_LEN + 256 + 1];
	size_t done = 0, tlen = 0;
	hl_u8 counter = 1;
	static const hl_u8 zeros[HL_SHA256_LEN] = { 0 };

	if (slen == 0) {
		salt = zeros;
		slen = sizeof zeros;
	}
	hl_hmac_sha256(salt, slen, ikm, ilen, prk);
	if (nlen > 256)
		nlen = 256;   /* HOPE's labels are short */
	while (done < olen) {
		size_t blen = 0, take;
		memcpy(block, t, tlen);
		blen += tlen;
		memcpy(block + blen, info, nlen);
		blen += nlen;
		block[blen++] = counter++;
		hl_hmac_sha256(prk, sizeof prk, block, blen, t);
		tlen = sizeof t;
		take = olen - done < tlen ? olen - done : tlen;
		memcpy(out + done, t, take);
		done += take;
	}
}

/* ---------- ChaCha20 ---------- */

#define QR(a, b, c, d) \
	a += b; d ^= a; d = ROTL(d, 16); \
	c += d; b ^= c; b = ROTL(b, 12); \
	a += b; d ^= a; d = ROTL(d, 8); \
	c += d; b ^= c; b = ROTL(b, 7);

static void chacha_block(const hl_u8 key[32], hl_u32 counter, const hl_u8 nonce[12], hl_u8 out[64])
{
	hl_u32 s[16], x[16];
	int i;
	s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
	for (i = 0; i < 8; i++)
		s[4 + i] = le32(key + 4 * i);
	s[12] = counter;
	s[13] = le32(nonce);
	s[14] = le32(nonce + 4);
	s[15] = le32(nonce + 8);
	memcpy(x, s, sizeof s);
	for (i = 0; i < 10; i++) {
		QR(x[0], x[4], x[8], x[12]) QR(x[1], x[5], x[9], x[13])
		QR(x[2], x[6], x[10], x[14]) QR(x[3], x[7], x[11], x[15])
		QR(x[0], x[5], x[10], x[15]) QR(x[1], x[6], x[11], x[12])
		QR(x[2], x[7], x[8], x[13]) QR(x[3], x[4], x[9], x[14])
	}
	for (i = 0; i < 16; i++)
		put_le32(out + 4 * i, x[i] + s[i]);
}

static void chacha_xor(const hl_u8 key[32], hl_u32 counter, const hl_u8 nonce[12],
                       const hl_u8 *in, size_t len, hl_u8 *out)
{
	hl_u8 ks[64];
	size_t i, j;
	for (i = 0; i < len; i += 64) {
		size_t n = len - i < 64 ? len - i : 64;
		chacha_block(key, counter++, nonce, ks);
		for (j = 0; j < n; j++)
			out[i + j] = in[i + j] ^ ks[j];
	}
}

/* ---------- Poly1305 (26-bit limbs, 64-bit products) ---------- */

typedef struct {
	hl_u32 r[5], h[5], pad[4];
} poly_ctx;

static void poly_init(poly_ctx *p, const hl_u8 key[32])
{
	p->r[0] = (le32(key + 0)) & 0x3ffffff;
	p->r[1] = (le32(key + 3) >> 2) & 0x3ffff03;
	p->r[2] = (le32(key + 6) >> 4) & 0x3ffc0ff;
	p->r[3] = (le32(key + 9) >> 6) & 0x3f03fff;
	p->r[4] = (le32(key + 12) >> 8) & 0x00fffff;
	p->h[0] = p->h[1] = p->h[2] = p->h[3] = p->h[4] = 0;
	p->pad[0] = le32(key + 16);
	p->pad[1] = le32(key + 20);
	p->pad[2] = le32(key + 24);
	p->pad[3] = le32(key + 28);
}

/* One 16-byte block; `hibit` is 1<<24 for a full block, 0 for the padded last one. */
static void poly_block(poly_ctx *p, const hl_u8 m[16], hl_u32 hibit)
{
	hl_u32 r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
	hl_u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	hl_u32 h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
	hl_u64 d0, d1, d2, d3, d4;
	hl_u32 c;

	h0 += (le32(m + 0)) & 0x3ffffff;
	h1 += (le32(m + 3) >> 2) & 0x3ffffff;
	h2 += (le32(m + 6) >> 4) & 0x3ffffff;
	h3 += (le32(m + 9) >> 6) & 0x3ffffff;
	h4 += (le32(m + 12) >> 8) | hibit;

	d0 = (hl_u64)h0 * r0 + (hl_u64)h1 * s4 + (hl_u64)h2 * s3 + (hl_u64)h3 * s2 + (hl_u64)h4 * s1;
	d1 = (hl_u64)h0 * r1 + (hl_u64)h1 * r0 + (hl_u64)h2 * s4 + (hl_u64)h3 * s3 + (hl_u64)h4 * s2;
	d2 = (hl_u64)h0 * r2 + (hl_u64)h1 * r1 + (hl_u64)h2 * r0 + (hl_u64)h3 * s4 + (hl_u64)h4 * s3;
	d3 = (hl_u64)h0 * r3 + (hl_u64)h1 * r2 + (hl_u64)h2 * r1 + (hl_u64)h3 * r0 + (hl_u64)h4 * s4;
	d4 = (hl_u64)h0 * r4 + (hl_u64)h1 * r3 + (hl_u64)h2 * r2 + (hl_u64)h3 * r1 + (hl_u64)h4 * r0;

	c = (hl_u32)(d0 >> 26); h0 = (hl_u32)d0 & 0x3ffffff;
	d1 += c; c = (hl_u32)(d1 >> 26); h1 = (hl_u32)d1 & 0x3ffffff;
	d2 += c; c = (hl_u32)(d2 >> 26); h2 = (hl_u32)d2 & 0x3ffffff;
	d3 += c; c = (hl_u32)(d3 >> 26); h3 = (hl_u32)d3 & 0x3ffffff;
	d4 += c; c = (hl_u32)(d4 >> 26); h4 = (hl_u32)d4 & 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
	h1 += c;

	p->h[0] = h0; p->h[1] = h1; p->h[2] = h2; p->h[3] = h3; p->h[4] = h4;
}

/* Feeds `len` bytes, zero-padding the last block to 16 (as the AEAD construction does). */
static void poly_padded(poly_ctx *p, const hl_u8 *m, size_t len)
{
	hl_u8 last[16];
	while (len >= 16) {
		poly_block(p, m, 1 << 24);
		m += 16;
		len -= 16;
	}
	if (len > 0) {
		memset(last, 0, sizeof last);
		memcpy(last, m, len);
		poly_block(p, last, 1 << 24);
	}
}

static void poly_finish(poly_ctx *p, hl_u8 tag[16])
{
	hl_u32 h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
	hl_u32 g0, g1, g2, g3, g4, c, mask;
	hl_u64 f;

	c = h1 >> 26; h1 &= 0x3ffffff;
	h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
	h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
	h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
	h1 += c;

	/* h - p, kept only if it didn't go negative */
	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1 << 26);
	mask = (g4 >> 31) - 1;
	g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

	h0 = (h0) | (h1 << 26);
	h1 = (h1 >> 6) | (h2 << 20);
	h2 = (h2 >> 12) | (h3 << 14);
	h3 = (h3 >> 18) | (h4 << 8);

	f = (hl_u64)h0 + p->pad[0]; h0 = (hl_u32)f;
	f = (hl_u64)h1 + p->pad[1] + (f >> 32); h1 = (hl_u32)f;
	f = (hl_u64)h2 + p->pad[2] + (f >> 32); h2 = (hl_u32)f;
	f = (hl_u64)h3 + p->pad[3] + (f >> 32); h3 = (hl_u32)f;

	put_le32(tag + 0, h0);
	put_le32(tag + 4, h1);
	put_le32(tag + 8, h2);
	put_le32(tag + 12, h3);
}

static void aead_tag(const hl_u8 key[32], const hl_u8 nonce[12], const hl_u8 *ad, size_t adlen,
                     const hl_u8 *ct, size_t len, hl_u8 tag[16])
{
	hl_u8 otk[64], lens[16];
	poly_ctx p;
	chacha_block(key, 0, nonce, otk);
	poly_init(&p, otk);
	poly_padded(&p, ad, adlen);
	poly_padded(&p, ct, len);
	memset(lens, 0, sizeof lens);
	/* le64(associated data length), le64(ciphertext length) */
	put_le32(lens + 0, (hl_u32)adlen);
	put_le32(lens + 8, (hl_u32)len);
	put_le32(lens + 12, (hl_u32)((hl_u64)len >> 32));
	poly_block(&p, lens, 1 << 24);
	poly_finish(&p, tag);
}

void hl_aead_seal_ad(const hl_u8 key[32], const hl_u8 nonce[12], const hl_u8 *ad, size_t adlen,
                     const hl_u8 *in, size_t len, hl_u8 *out)
{
	chacha_xor(key, 1, nonce, in, len, out);
	aead_tag(key, nonce, ad, adlen, out, len, out + len);
}

void hl_aead_seal(const hl_u8 key[32], const hl_u8 nonce[12], const hl_u8 *in, size_t len, hl_u8 *out)
{
	hl_aead_seal_ad(key, nonce, NULL, 0, in, len, out);
}

int hl_aead_open(const hl_u8 key[32], const hl_u8 nonce[12], const hl_u8 *in, size_t len, hl_u8 *out)
{
	hl_u8 tag[16], diff = 0;
	size_t i;
	if (len < 16)
		return -1;
	len -= 16;
	aead_tag(key, nonce, NULL, 0, in, len, tag);
	for (i = 0; i < 16; i++)
		diff |= tag[i] ^ in[len + i];
	if (diff != 0)
		return -1;
	chacha_xor(key, 1, nonce, in, len, out);
	return 0;
}

int hl_random(hl_u8 *out, size_t n)
{
	FILE *f = fopen("/dev/urandom", "rb");
	size_t got;
	if (!f)
		return -1;
	got = fread(out, 1, n, f);
	fclose(f);
	return got == n ? 0 : -1;
}
