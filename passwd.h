#ifndef __PASSWD_H__
#define __PASSWD_H__

#include "stralloc.h"

/* returns 0 on success else a errro number is returned (see qldap-errno.h) */
int cmp_passwd(char *, char *);

/* make a password */
int make_passwd(const char *, char *, stralloc *);

/* feed salt pool for passwd generation */
int feed_salt(char *, int);

/* feed crypt(3) format to the passwd function */
void feed_crypt(const char *);

#endif
