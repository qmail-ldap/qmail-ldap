/* auth_mod.h, jeker@n-r-g.com, best viewed with tabsize = 4 */
#ifndef __AUTH_MOD_H__
#define __AUTH_MOD_H__

#include "stralloc.h"

extern unsigned int auth_port;

void auth_init(int argc, char **argv, stralloc *login, stralloc *authdata);
/* this function should return the 0-terminated string login and authdata
 * argc and argv are the arguments of the next auth_module. */

void auth_fail(int argc, char **argv, char *login);
/* Checks if it was a hard fail (bad password) or just a soft error 
 * (user not found) argc and argv are the arguments of the next auth_module. */

void auth_success(int argc, char **argv, char *login, int uid, int gid,
	   			  char* home, char *homemaker, char *md);
/* starts the next auth_module, or what ever (argv ... ) */

void auth_error(void);
/* error handler, for this module, does not return */

void auth_forward(int fd, char *login, char *passwd);
/* for connection forwarding, makes the login part and returns after sending the
 * latest command immidiatly */

#endif
