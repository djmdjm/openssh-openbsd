/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains various auxiliary functions related to multiple
 * precision integers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* RCSID("$OpenBSD: mpaux.h,v 1.8.2.5 2001/09/27 00:15:42 miod Exp $"); */

#ifndef MPAUX_H
#define MPAUX_H

void	 compute_session_id(u_char[16], u_char[8], BIGNUM *, BIGNUM *);

#endif				/* MPAUX_H */
