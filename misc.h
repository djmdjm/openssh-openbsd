/*	$OpenBSD: misc.h,v 1.4.2.1 2001/09/27 19:03:54 jason Exp $	*/

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

char	*chop(char *);
char	*strdelim(char **);
void	 set_nonblock(int);
void	 unset_nonblock(int);
int	 a2port(const char *);
char	*cleanhostname(char *);
char	*colon(char *);
long	 convtime(const char *);

struct passwd *pwcopy(struct passwd *);

typedef struct arglist arglist;
struct arglist {
        char    **list;
        int     num;
        int     nalloc;
};
void	 addargs(arglist *, char *, ...) __attribute__((format(printf, 2, 3)));
