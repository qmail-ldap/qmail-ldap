#ifndef _CHECK_H_
#define _CHECK_H_

extern int chck_userb();
extern int chck_pathb();

extern int chck_users();
extern int chck_paths();

/* use escape_forldap function to escape possible mailaddresses  *
 * to a secure format for the LDAP search (escapeing '*', '(' &  *
 * ')' with a '\'                                                */
extern int escape_forldap();



#endif
