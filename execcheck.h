#ifndef __EXECCHECK_H__
#define __EXECCHECK_H__

struct qmail;

void execcheck_setup(void);
void execcheck_start(void);
int execcheck_on(void);
int execcheck_flag(void);
void execcheck_put(struct qmail *, const char *);

#endif
