/* $OpenBSD: poly1305.h,v 1.2 2013/12/19 22:57:13 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#ifndef POLY1305_H
#define POLY1305_H

#include <sys/types.h>

#define POLY1305_KEYLEN		32
#define POLY1305_TAGLEN		16

void poly1305_auth(unsigned char out[POLY1305_TAGLEN], const unsigned char *m, size_t inlen,
    const unsigned char key[POLY1305_KEYLEN]);

#endif	/* POLY1305_H */
