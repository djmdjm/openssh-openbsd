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

#ifndef _OPENSSL_WRAP_H
#define _OPENSSL_WRAP_H

#ifdef WITH_OPENSSL

struct sshdh;
struct sshbn;
struct sshbuf;
struct ssh;

/* Allocate a new Diffie-Hellman context. Returns NULL on failure. */
struct sshdh *sshdh_new(void);

/* Frees a Diffie-Hellman context. */
void sshdh_free(struct sshdh *dh);

/* Accessors for Diffie-Hellman parameters. Caller must free returned values. */
struct sshbn *sshdh_pubkey(struct sshdh *dh);
struct sshbn *sshdh_p(struct sshdh *dh);
struct sshbn *sshdh_g(struct sshdh *dh);

/* Dump a Diffie-Hellman context to stderr (for debugging) */
void sshdh_dump(struct sshdh *dh);

/*
 * Generate a Diffie-Hellman private key. NB. The 'dh' context's group
 * information must be initialised.
 * Returns a ssherr.h code on failure or 0 on success.
 */
int sshdh_generate(struct sshdh *dh, size_t len);

/*
 * Compute a shared key using Diffie-Hellman. The 'dh' context must
 * previously have had sshdh_generate() called.
 */
int sshdh_compute_key(struct sshdh *dh, struct sshbn *pubkey,
    struct sshbn **shared_secretp);

/*
 * Initialise the group information for a Diffie-Hellman from explicit
 * hexadecimal generator and modulus values.
 * Returns a ssherr.h code on failure or 0 on success.
 */
int sshdh_new_group_hex(const char *gen, const char *modulus,
    struct sshdh **dhp);

/*
 * Initialise the group information for a Diffie-Hellman from explicit
 * generator and modulus values.
 * NB. After this call, ownership of 'gen' and 'modulus' is transferred
 * to the returned Diffie-Hellman context. The caller should not free them.
 */
struct sshdh *sshdh_new_group(struct sshbn *gen, struct sshbn *modulus);

/* Allocate a new, zero arbitrary precision integer (bignum) */
struct sshbn *sshbn_new(void);

/* Clear and free a bignum */
void sshbn_free(struct sshbn *bn);

/*
 * Allocate a bignum and initialise it from the specified data, which is
 * interpreted as unsigned big endian.
 * Returns a ssherr.h code on failure or 0 on success.
 */
int sshbn_from(const void *d, size_t l, struct sshbn **retp);

/*
 * Allocate a bignum and initialise it from the hexadecimal string provided.
 * Returns a ssherr.h code on failure or 0 on success.
 */
int sshbn_from_hex(const char *hex, struct sshbn **retp);

/* Returns the number of bits in the bignum, or zero on error */
size_t sshbn_bits(const struct sshbn *bn);

/* Explicit bignums for zero and one */
const struct sshbn *sshbn_value_0(void);
const struct sshbn *sshbn_value_1(void);

/*
 * Compare two bignums, returning -1 if 'a' is less than 'b', 0 if 'a' is
 * equal to 'b' or 1 if 'a' is greater than 'b'.
 */
int sshbn_cmp(const struct sshbn *a, const struct sshbn *b);

/*
 * Calculate r = b - a.
 * Returns a ssherr.h code on failure or 0 on success.
 */
int sshbn_sub(struct sshbn *r, const struct sshbn *a, const struct sshbn *b);

/*
 * Tests whether the i'th bit of the bignum is set, basically
 * returning "(bn & (1 << i)) != 0".
 */
int sshbn_is_bit_set(const struct sshbn *bn, size_t i);

/* XXX move to sshbuf.h; rename s/_wrap$// */
int sshbuf_get_bignum2_wrap(struct sshbuf *buf, struct sshbn *bn);
int sshbuf_get_bignum1_wrap(struct sshbuf *buf, struct sshbn *bn);
int sshbuf_put_bignum2_wrap(struct sshbuf *buf, const struct sshbn *bn);
int sshbuf_put_bignum1_wrap(struct sshbuf *buf, const struct sshbn *bn);
int sshpkt_get_bignum2_wrap(struct ssh *ssh, struct sshbn *bn);
int sshpkt_put_bignum2_wrap(struct ssh *ssh, const struct sshbn *bn);

/* bridge to unwrapped OpenSSL APIs; XXX remove later */
struct sshbn *sshbn_from_bignum(BIGNUM *bn);
BIGNUM *sshbn_bignum(struct sshbn *bn);
DH *sshdh_dh(struct sshdh *dh);

#endif /* WITH_OPENSSL */

#endif /* _OPENSSL_WRAP_H */
