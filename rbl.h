#ifndef RBL_H
#define RBL_H

#include "qmail.h"

extern void rblheader(struct qmail *);
extern int rblcheck(const char *, char **, int);
extern int rblinit(void);

#endif
