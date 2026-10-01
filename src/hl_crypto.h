/*
 * purple-hotline: the cryptography HOPE needs, with no outside library.
 *
 * SHA-256, SHA-1, HMAC, HKDF-SHA256 and ChaCha20-Poly1305 (RFC 8439). Written in
 * plain C that old compilers (GCC 4.0 on a PowerPC Mac) accept: every multi-byte
 * value is read and written a byte at a time, so it is right on big- and
 * little-endian machines alike.
 *
 * Copyright (c) 2026 John Leighow. MIT license (see LICENSE).
 */
#ifndef HL_CRYPTO_H
#define HL_CRYPTO_H

#include <stddef.h>

typedef unsigned char hl_u8;
typedef unsigned int hl_u32;   /* 32 bits on every Mac and PC this targets */

#define HL_SHA256_LEN 32
#define HL_SHA1_LEN 20

typedef struct {
	hl_u32 h[8];
	hl_u8 buf[64];
	hl_u32 used;
	hl_u32 len_hi, len_lo;   /* message length in bytes, as two halves */
} hl_sha256_ctx;

typedef struct {
	hl_u32 h[5];
	hl_u8 buf[64];
	hl_u32 used;
	hl_u32 len_hi, len_lo;
} hl_sha1_ctx;

void hl_sha256_init(hl_sha256_ctx *c);
void hl_sha256_update(hl_sha256_ctx *c, const hl_u8 *p, size_t n);
void hl_sha256_final(hl_sha256_ctx *c, hl_u8 out[HL_SHA256_LEN]);

void hl_sha1_init(hl_sha1_ctx *c);
void hl_sha1_update(hl_sha1_ctx *c, const hl_u8 *p, size_t n);
void hl_sha1_final(hl_sha1_ctx *c, hl_u8 out[HL_SHA1_LEN]);

/* HMAC with SHA-256 or SHA-1; `out` takes 32 or 20 bytes. */
void hl_hmac_sha256(const hl_u8 *key, size_t klen, const hl_u8 *msg, size_t mlen, hl_u8 out[HL_SHA256_LEN]);
void hl_hmac_sha1(const hl_u8 *key, size_t klen, const hl_u8 *msg, size_t mlen, hl_u8 out[HL_SHA1_LEN]);

/* HKDF-SHA256 (RFC 5869), at most 255*32 bytes out. */
void hl_hkdf_sha256(const hl_u8 *ikm, size_t ilen, const hl_u8 *salt, size_t slen,
                    const hl_u8 *info, size_t nlen, hl_u8 *out, size_t olen);

/* ChaCha20-Poly1305 AEAD with no associated data (as HOPE uses it).
 * Seal writes len + 16 bytes; open returns 0 when the tag checks out (then
 * `out` holds len - 16 bytes) and -1 when it doesn't. */
void hl_aead_seal(const hl_u8 key[32], const hl_u8 nonce[12], const hl_u8 *in, size_t len, hl_u8 *out);
/* The same with associated data (only the tests use it, against RFC 8439's vector). */
void hl_aead_seal_ad(const hl_u8 key[32], const hl_u8 nonce[12], const hl_u8 *ad, size_t adlen,
                     const hl_u8 *in, size_t len, hl_u8 *out);
int hl_aead_open(const hl_u8 key[32], const hl_u8 nonce[12], const hl_u8 *in, size_t len, hl_u8 *out);

/* Fills `out` with random bytes from the system (/dev/urandom). 0 on success. */
int hl_random(hl_u8 *out, size_t n);

#endif
