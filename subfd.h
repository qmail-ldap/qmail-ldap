#ifndef SUBFD_H
#define SUBFD_H

#include "substdio.h"

extern substdio *subfdin;
extern substdio *subfdinsmall;
extern substdio *subfdout;
extern substdio *subfdoutsmall;
extern substdio *subfderr;

extern int subfd_read(int, char *, int);
extern int subfd_readsmall(int, char *, int);

#endif
