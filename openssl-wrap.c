/*
 * Copyright (c) 2015 Damien Miller <djm@mindrot.org>
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "sshbuf.h"
#include "packet.h"
#include "ssherr.h"
#include "openssl-wrap.h"

struct sshdh {
	DH *dh;
};

struct sshbn {
	BIGNUM *bn;
};

static struct sshbn *
bnwrap(BIGNUM *bn)
{
	struct sshbn *ret;

	if (bn == NULL)
		return NULL;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->bn = BN_dup(bn)) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

/* DH wrappers */

struct sshdh *
sshdh_new(void)
{
	struct sshdh *ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->dh = DH_new()) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

void
sshdh_free(struct sshdh *dh)
{
	if (dh != NULL) {
		if (dh->dh != NULL)
			DH_free(dh->dh);
		explicit_bzero(dh, sizeof(*dh));
		free(dh);
	}
}

struct sshbn *
sshdh_pubkey(struct sshdh *dh)
{
	return bnwrap(dh->dh->pub_key);
}

struct sshbn *
sshdh_p(struct sshdh *dh)
{
	return bnwrap(dh->dh->p);
}

struct sshbn *
sshdh_g(struct sshdh *dh)
{
	return bnwrap(dh->dh->g);
}

void
sshdh_dump(struct sshdh *dh)
{
	DHparams_print_fp(stderr, dh->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, dh->dh->pub_key);
	fprintf(stderr, "\n");
}

// XXX needed?
size_t
sshdh_shared_key_size(struct sshdh *dh)
{
	int sz;

	if (dh == NULL || dh->dh == NULL || (sz = DH_size(dh->dh)) < 0)
		return 0;
	return (size_t)sz;
}

int sshdh_compute_key(struct sshdh *dh, struct sshbn *pubkey,
    struct sshbn **shared_secretp)
{
	u_char *sbuf;
	int r, slen;

	*shared_secretp = NULL;
	if ((slen = DH_size(dh->dh)) <= 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((sbuf = calloc(1, slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = DH_compute_key(sbuf, pubkey->bn, dh->dh)) < 0 ||
	    r != slen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((r = sshbn_from(sbuf, slen, shared_secretp)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	explicit_bzero(sbuf, slen);
	free(sbuf);
	return r;
}

int
sshdh_generate(struct sshdh *dh, size_t len)
{
	if (len > INT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;
	if (len != 0)
		dh->dh->length = (int)len;
	if (DH_generate_key(dh->dh) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

int
sshdh_new_group_hex(const char *gen, const char *modulus, struct sshdh **dhp)
{
	struct sshdh *ret;

	*dhp = NULL;
	if ((ret = sshdh_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (BN_hex2bn(&ret->dh->p, modulus) == 0 ||
	    BN_hex2bn(&ret->dh->g, gen) == 0) {
		sshdh_free(ret);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*dhp = ret;
	return 0;
}

/* XXX transfers ownership of gen, modulus */
struct sshdh *
sshdh_new_group(struct sshbn *gen, struct sshbn *modulus)
{
	struct sshdh *dh;

	if ((dh = sshdh_new()) == NULL)
		return NULL;
	dh->dh->p = modulus->bn;
	dh->dh->g = gen->bn;
	modulus->bn = gen->bn = NULL;
	sshbn_free(gen);
	sshbn_free(modulus);
	return (dh);
}


/* BIGNUM wrappers */

struct sshbn *
sshbn_new(void)
{
	return bnwrap(BN_new());
}

void
sshbn_free(struct sshbn *bn)
{
	if (bn != NULL) {
		if (bn->bn != NULL)
			BN_clear_free(bn->bn);
		explicit_bzero(bn, sizeof(*bn));
		free(bn);
	}
}

int
sshbn_from(const void *d, size_t l, struct sshbn **retp)
{
	struct sshbn *ret;
	const u_char *dd = (const u_char *)d;

	*retp = NULL;
	if (l > INT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((ret = sshbn_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (BN_bin2bn(dd, (int)l, ret->bn) == NULL) {
		sshbn_free(ret);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*retp = ret;
	return 0;
}

int
sshbn_from_hex(const char *hex, struct sshbn **retp)
{
	struct sshbn *ret;

	*retp = NULL;
	if ((ret = sshbn_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (BN_hex2bn(&ret->bn, hex) <= 0) {
		sshbn_free(ret);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*retp = ret;
	return 0;
}

size_t
sshbn_bits(const struct sshbn *bn)
{
	int bits = BN_num_bits(bn->bn);

	return bits < 0 ? 0 : (size_t)bits;
}

const struct sshbn *
sshbn_value_0(void)
{
	static struct sshbn *ret;

	if (ret == NULL)
		sshbn_from_hex("0", &ret);
	return ret;
}

const struct sshbn *
sshbn_value_1(void)
{
	static struct sshbn *ret;

	if (ret == NULL)
		sshbn_from_hex("1", &ret);
	return ret;
}

int
sshbn_cmp(const struct sshbn *a, const struct sshbn *b)
{
	return BN_cmp(a->bn, b->bn);
}

int
sshbn_sub(struct sshbn *r, const struct sshbn *a, const struct sshbn *b)
{
	if (BN_sub(r->bn, a->bn, b->bn) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

int
sshbn_is_bit_set(const struct sshbn *bn, size_t i)
{
	if (i > INT_MAX)
		return 0;
	return BN_is_bit_set(bn->bn, (int)i);
}

/* XXX move to sshbuf.h */
int
sshbuf_get_bignum2_wrap(struct sshbuf *buf, struct sshbn *bn)
{
	return sshbuf_get_bignum2(buf, bn->bn);
}

int
sshbuf_put_bignum2_wrap(struct sshbuf *buf, const struct sshbn *bn)
{
	return sshbuf_put_bignum2(buf, bn->bn);
}

int
sshpkt_get_bignum2_wrap(struct ssh *ssh, struct sshbn *bn)
{
	return sshpkt_get_bignum2(ssh, bn->bn);
}

int
sshpkt_put_bignum2_wrap(struct ssh *ssh, const struct sshbn *bn)
{
	return sshpkt_put_bignum2(ssh, bn->bn);
}

/* bridge to unwrapped OpenSSL APIs; XXX remove later */
BIGNUM *
sshbn_bignum(struct sshbn *bn)
{
	return bn->bn;
}

DH *sshdh_dh(struct sshdh *dh)
{
	return dh->dh;
}

struct sshbn *
sshbn_from_bignum(BIGNUM *bn)
{
	return bnwrap(bn);
}

