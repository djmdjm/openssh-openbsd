/*	$OpenBSD: hostfile.h,v 1.7.2.1 2001/09/27 19:03:54 jason Exp $	*/

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
#ifndef HOSTFILE_H
#define HOSTFILE_H

typedef enum {
	HOST_OK, HOST_NEW, HOST_CHANGED
}       HostStatus;

HostStatus
check_host_in_hostfile(const char *, const char *, Key *, Key *, int *);
int	 add_host_to_hostfile(const char *, const char *, Key *);
int	 auth_rsa_read_key(char **, u_int *, BIGNUM *, BIGNUM *);

#endif
