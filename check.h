#ifndef _CHECK_H_
#define _CHECK_H_

#include "str.h"

extern int chck_mailb(char *s, register unsigned int len);
extern int chck_userb(char *s, register unsigned int len);
extern long chck_idb(char *s, register unsigned int len);
extern int chck_pathb(char *s, register unsigned int len);

extern int chck_mails(char *s);
extern int chck_users(char *s);
extern long chck_ids(char *s);
extern int chck_paths(char *s);


#endif
