#ifndef __SMTPCALL_H__
#define __SMTPCALL_H__

#include "stralloc.h"
#include "substdio.h"

struct call {
  int flagerr;
  int flagabort;
  int flagstar;
  unsigned long pid;
  int tofd;
  int fromfd;
  substdio ssto;
  substdio ssfrom;
  char tobuf[256];
  char frombuf[128];
} ;

int call_getln(substdio *, stralloc *);
int call_getc(struct call *, char *);
int call_put(struct call *, const char *, unsigned int);
int call_puts(struct call *, const char *);
int call_flush(struct call *);
int call_putflush(struct call *, const char *, unsigned int);
int call_putsflush(struct call *, const char *);
int call_open(struct call *, const char *, int, int);
void call_close(struct call *);

const char *auth_close(struct call *, stralloc *, const char *);

#endif
