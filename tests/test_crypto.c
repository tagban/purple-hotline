/* Known-answer tests for hl_crypto (published vectors). */
#include "../src/hl_crypto.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void unhex(const char *s, hl_u8 *out, size_t *len)
{
	size_t n = 0;
	while (s[0] && s[1]) {
		unsigned v;
		if (s[0] == ' ' || s[0] == ':') { s++; continue; }
		sscanf(s, "%2x", &v);
		out[n++] = (hl_u8)v;
		s += 2;
	}
	*len = n;
}

static void check(const char *name, const hl_u8 *got, size_t n, const char *want_hex)
{
	hl_u8 want[512];
	size_t wl;
	unhex(want_hex, want, &wl);
	if (wl != n || memcmp(got, want, n) != 0) {
		size_t i;
		printf("FAIL %s\n  got  ", name);
		for (i = 0; i < n; i++) printf("%02x", got[i]);
		printf("\n");
		failures++;
	} else {
		printf("ok   %s\n", name);
	}
}

int main(void)
{
	hl_u8 out[512], key[64], nonce[12], buf[512], ad[32];
	size_t kl, nl, al;
	hl_sha256_ctx s;
	hl_sha1_ctx s1;
	const char *lg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
	size_t i;

	hl_sha256_init(&s);
	hl_sha256_update(&s, (const hl_u8 *)"abc", 3);
	hl_sha256_final(&s, out);
	check("SHA-256 abc", out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	/* a million a's, fed unevenly, crosses many block and length boundaries */
	hl_sha256_init(&s);
	memset(buf, 'a', 333);
	for (i = 0; i < 1000000 / 333; i++)
		hl_sha256_update(&s, buf, 333);
	hl_sha256_update(&s, buf, 1000000 % 333);
	hl_sha256_final(&s, out);
	check("SHA-256 million a", out, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

	hl_sha1_init(&s1);
	hl_sha1_update(&s1, (const hl_u8 *)"abc", 3);
	hl_sha1_final(&s1, out);
	check("SHA-1 abc", out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");

	hl_hmac_sha256((const hl_u8 *)"Jefe", 4, (const hl_u8 *)"what do ya want for nothing?", 28, out);
	check("HMAC-SHA256 RFC 4231 #2", out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

	/* RFC 4231 #6: a key longer than the block */
	memset(buf, 0xaa, 131);
	hl_hmac_sha256(buf, 131, (const hl_u8 *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
	check("HMAC-SHA256 RFC 4231 #6", out, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

	hl_hmac_sha1((const hl_u8 *)"Jefe", 4, (const hl_u8 *)"what do ya want for nothing?", 28, out);
	check("HMAC-SHA1 RFC 2202 #2", out, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

	/* RFC 5869 test case 1 */
	memset(key, 0x0b, 22);
	unhex("000102030405060708090a0b0c", buf, &kl);
	unhex("f0f1f2f3f4f5f6f7f8f9", ad, &al);
	hl_hkdf_sha256(key, 22, buf, kl, ad, al, out, 42);
	check("HKDF RFC 5869 #1", out, 42,
	      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

	/* RFC 8439 2.8.2 */
	for (i = 0; i < 32; i++)
		key[i] = (hl_u8)(0x80 + i);
	unhex("070000004041424344454647", nonce, &nl);
	unhex("50515253c0c1c2c3c4c5c6c7", ad, &al);
	hl_aead_seal_ad(key, nonce, ad, al, (const hl_u8 *)lg, strlen(lg), out);
	check("ChaCha20-Poly1305 RFC 8439 2.8.2", out, strlen(lg) + 16,
	      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
	      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
	      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
	      "3ff4def08e4b7a9de576d26586cec64b6116"
	      "1ae10b594f09e26a7e902ecbd0600691");

	/* round trip without associated data, and a flipped bit is refused */
	hl_aead_seal(key, nonce, (const hl_u8 *)lg, strlen(lg), out);
	if (hl_aead_open(key, nonce, out, strlen(lg) + 16, buf) != 0 || memcmp(buf, lg, strlen(lg)) != 0) {
		printf("FAIL AEAD round trip\n");
		failures++;
	} else {
		printf("ok   AEAD round trip\n");
	}
	out[5] ^= 1;
	if (hl_aead_open(key, nonce, out, strlen(lg) + 16, buf) == 0) {
		printf("FAIL AEAD accepted a tampered frame\n");
		failures++;
	} else {
		printf("ok   AEAD refuses a tampered frame\n");
	}

	if (failures)
		printf("%d failed\n", failures);
	else
		printf("all good\n");
	return failures != 0;
}
