#include <assert.h>
#include "ssh.h"

int crypto_scalarmult_curve25519(unsigned char a[CURVE25519_SIZE],
                                 const unsigned char b[CURVE25519_SIZE],
                                 const unsigned char c[CURVE25519_SIZE]);

static const struct ssh_kex ssh_c25519_kex_sha256 = {
    "curve25519-sha256@libssh.org", NULL,
    KEXTYPE_C25519, NULL, NULL, 0, 0, &ssh_sha256
};

static const struct ssh_kex *const c25519_kex_list[] = {
    &ssh_c25519_kex_sha256,
};

const struct ssh_kexes ssh_c25519_kex = {
    sizeof(c25519_kex_list) / sizeof(*c25519_kex_list),
    c25519_kex_list
};

void c25519_init(struct c25519_ctx *ctx)
{
	static const unsigned char basepoint[CURVE25519_SIZE] = {9};

	/* Create an ephemeral client key and generate a matching pubkey */
	for (size_t i = 0; i < CURVE25519_SIZE; i++)
	    ctx->client_key[i] = random_byte();
	crypto_scalarmult_curve25519(ctx->client_pubkey,
                                 ctx->client_key, basepoint);
}

static Bignum c25519_bignum_to_ssh1_bignum(const unsigned char *in,
                                           size_t inlen)
{
    Bignum ret;
    unsigned char *buf, *p;
    size_t pad = 0;
    int c;

    p = buf = snewn(inlen + 1, unsigned char);
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
    if (inlen > 0 && (in[0] & 0x80)) {
        *p++ = 0;
        pad = 1;
    }
    memcpy(p, in, inlen);
    ret = bignum_from_bytes(buf, inlen + pad);
    smemclr(buf, inlen + 1);
    sfree(buf);
    return ret;
}

Bignum c25519_mix(struct c25519_ctx *ctx)
{
    Bignum ret;
    unsigned char shared_key[CURVE25519_SIZE];
	crypto_scalarmult_curve25519(shared_key, ctx->client_key,
                                 ctx->server_pubkey);
    ret = c25519_bignum_to_ssh1_bignum(shared_key, CURVE25519_SIZE);
    smemclr(shared_key, sizeof shared_key);
    return ret;
}

void c25519_cleanup(void *handle)
{
    struct c25519_ctx *ctx = (struct c25519_ctx *)handle;
    smemclr(ctx->client_key, CURVE25519_SIZE);
    smemclr(ctx->client_pubkey, CURVE25519_SIZE);
    sfree(ctx);
}
