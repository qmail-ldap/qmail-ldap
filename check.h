#ifndef _CHECK_H_
#define _CHECK_H_


#define DENY_ALL	0x00
#define ALLOW_USER	0x01
#define ALLOW_PATH	0x02
#define ALLOW_PROG	0x04
#define ALLOW_ALL	(ALLOW_USER | ALLOW_PATH | ALLOW_PROG)
#define DENY_USER	(unsigned char) ~ALLOW_USER
#define DENY_PATH	(unsigned char) ~ALLOW_PATH
#define DENY_PROG	(unsigned char) ~ALLOW_PROG
#define NOT_FIRST	0x80


extern int sanitycheckb(register char *s, register unsigned int len,
						register unsigned char mask);
extern int sanitychecks(register char *s, register unsigned char mask);

extern int sanitypathcheckb(register char *s, register unsigned int len,
						register unsigned char mask);
extern int sanitypathchecks(register char *s, register unsigned char mask);

#define chck_userb(str, len)	sanitycheckb(str, len, ALLOW_USER)
#define chck_users(str)			sanitychecks(str, ALLOW_USER)

#define chck_pathb(str, len)	sanitypathcheckb(str, len, ALLOW_PATH)
#define chck_paths(str)			sanitypathchecks(str, ALLOW_PATH)

#define chck_progb(str, len)	sanitycheckb(str, len, ALLOW_PROG)
#define chck_progs(str)			sanitychecks(str, ALLOW_PROG)

#endif
