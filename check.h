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


extern int sanitycheckb(char *, unsigned int, unsigned char);
extern int sanitychecks(char *, unsigned char);

extern int sanitypathcheckb(char *, unsigned int , unsigned char);
extern int sanitypathchecks(char *, unsigned char);

#define check_userb(str, len)	sanitycheckb((str), (len), ALLOW_USER)
#define check_users(str)	sanitychecks((str), ALLOW_USER)

#define check_pathb(str, len)	sanitypathcheckb((str), (len), ALLOW_PATH)
#define check_paths(str)	sanitypathchecks((str), ALLOW_PATH)

#define check_progb(str, len)	sanitycheckb((str), (len), ALLOW_PROG)
#define check_progs(str)	sanitychecks((str), ALLOW_PROG)

#endif
