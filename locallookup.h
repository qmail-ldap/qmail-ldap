#ifndef __LOCALLOOKUP_H__
#define __LOCALLOOKUP_H__

struct credentials;

int check_passwd(stralloc *, stralloc *, struct credentials *, int);
int get_local_maildir(stralloc *, stralloc *);

#endif

