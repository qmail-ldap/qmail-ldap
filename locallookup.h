#ifndef __LOCALLOOKUP_H__
#define __LOCALLOOKUP_H__

#include "stralloc.h"

struct credentials;

int check_passwd(stralloc *, stralloc *, struct credentials *, int);
int get_local_maildir(stralloc *, stralloc *);

#endif

