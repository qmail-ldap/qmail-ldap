#ifndef _CHECK_H_
#define _CHECK_H_

#include "str.h"

/* extern int chck_mailb(); */ /* no longer used will be removed */
extern int chck_userb();
extern long chck_idb();
extern int chck_pathb();

/* extern int chck_mails(); */ /* no longer used will be removed */
extern int chck_users();
extern long chck_ids();
extern int chck_paths();

/* use escape_forldap function to escape possible mailaddresses  *
 * to a secure format for the LDAP search (escapeing '*', '(' &  *
 * ')' with a '\'                                                */
extern int escape_forldap();



#endif
