/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: cipher-chachapoly.c,v 1.4 2014/01/31 16:39:19 tedu Exp $ */

#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "ssh.h"
#include "misc.h"

static void
put_u64(void *vp, uint64_t v)
{
	unsigned char *p = (unsigned char *)vp;

	p[0] = (unsigned char)(v >> 56) & 0xff;
	p[1] = (unsigned char)(v >> 48) & 0xff;
	p[2] = (unsigned char)(v >> 40) & 0xff;
	p[3] = (unsigned char)(v >> 32) & 0xff;
	p[4] = (unsigned char)(v >> 24) & 0xff;
	p[5] = (unsigned char)(v >> 16) & 0xff;
	p[6] = (unsigned char)(v >> 8) & 0xff;
	p[7] = (unsigned char)v & 0xff;
}

static uint32_t
get_u32(const void *vp)
{
	const unsigned char *p = (const unsigned char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	return (v);
}

static int
timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
	const unsigned char *p1 = b1, *p2 = b2;
	int ret = 0;

	for (; n > 0; n--)
		ret |= *p1++ ^ *p2++;
	return (ret != 0);
}

#include "sshcipher-chachapoly.h"

void chachapoly_init(struct chachapoly_ctx *ctx,
    const unsigned char *key, unsigned int keylen)
{
	assert(keylen == (32 + 32)); /* 2 x 256 bit keys */
	chacha_keysetup(&ctx->main_ctx, key, 256);
	chacha_keysetup(&ctx->header_ctx, key + 32, 256);
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct chachapoly_ctx *ctx, unsigned int seqnr, unsigned char *dest,
    const unsigned char *src, unsigned int len, unsigned int aadlen, unsigned int authlen, int do_encrypt)
{
	unsigned char seqbuf[8];
	const unsigned char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	unsigned char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
	int r = -1;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_key, 0, sizeof(poly_key));
	put_u64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_key, poly_key, sizeof(poly_key));
	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const unsigned char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0)
			goto out;
	}
	/* Crypt additional data */
	if (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_key);
	}
	r = 0;

 out:
	smemclr(expected_tag, sizeof(expected_tag));
	smemclr(seqbuf, sizeof(seqbuf));
	smemclr(poly_key, sizeof(poly_key));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    unsigned int *plenp, unsigned int seqnr, const unsigned char *cp, unsigned int len)
{
	unsigned char buf[4], seqbuf[8];

	if (len < 4)
		return -1; /* Insufficient length */
	put_u64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = get_u32(buf);
	return 0;
}

void *chachapoly_make_context(void)
{
	return snew(struct chachapoly_ctx);
}

void chachapoly_free_context(void *handle)
{
	sfree(handle);
}

// ChaChaPoly uses the seqnum as the IV, and it is integrated in the
// crypt function, so this function is not required.
void chachapoly_iv(void *handle, unsigned char *iv)
{
	assert(0);
}

void chachapoly_key(void *handle, unsigned char *key)
{
	struct chachapoly_ctx *ctx = (struct chachapoly_ctx *)handle;
	chachapoly_init(ctx, key, 64);
}

void chachapoly_encrypt(void *handle, unsigned char *blk, int len)
{
	assert(0);
}

void chachapoly_decrypt(void *handle, unsigned char *blk, int len)
{
	assert(0);
}

static const struct ssh2_cipher ssh_chachapoly_openssh = {
	chachapoly_make_context, chachapoly_free_context, chachapoly_iv,
	chachapoly_key, chachapoly_encrypt, chachapoly_decrypt,
	"chacha20-poly1305@openssh.com",
	8, 512, SSH_CIPHER_IS_CHACHAPOLY, "ChaCha20-Poly1305"
};

static const struct ssh2_cipher *const chachapoly_list[] = {
	&ssh_chachapoly_openssh,
};

const struct ssh2_ciphers ssh2_chachapoly = {
	sizeof(chachapoly_list) / sizeof(*chachapoly_list),
	chachapoly_list
};

