#ifndef __CHECKPASSWORD_H__
#define __CHECKPASSWORD_H__

#include "stralloc.h"

struct credentials {
	int		uid;
	int		gid;
	stralloc	home;
	stralloc	maildir;
	stralloc	forwarder;
};

typedef int (*checkfunc)(stralloc *, stralloc *, struct credentials *, int);

int check(checkfunc *, stralloc *, stralloc *, struct credentials *, int);
int check_ldap(stralloc *, stralloc *, struct credentials *, int);
void check_credentials(struct credentials *);
void change_uid(int, int);
void setup_env(char *, struct credentials *);

#endif
