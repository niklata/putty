/* $OpenBSD: cipher-chachapoly.h,v 1.1 2013/11/21 00:45:44 djm Exp $ */

/*
 * Copyright (c) Damien Miller 2013 <djm@mindrot.org>
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
#ifndef CHACHA_POLY_AEAD_H
#define CHACHA_POLY_AEAD_H

#include <sys/types.h>
#include "sshchacha.h"
#include "sshpoly1305.h"

#define CHACHA_KEYLEN	32 /* Only 256 bit keys used here */
#define CHACHA_HEADERLEN 4

struct chachapoly_ctx {
	struct chacha_ctx main_ctx, header_ctx;
};

void chachapoly_init(struct chachapoly_ctx *cpctx,
    const unsigned char *key, unsigned int keylen);
int	chachapoly_crypt(struct chachapoly_ctx *cpctx, unsigned int seqnr,
    unsigned char *dest, const unsigned char *src, unsigned int len, unsigned int aadlen, unsigned int authlen,
    int do_encrypt);
int	chachapoly_get_length(struct chachapoly_ctx *cpctx,
    unsigned int *plenp, unsigned int seqnr, const unsigned char *cp, unsigned int len);

#endif /* CHACHA_POLY_AEAD_H */
