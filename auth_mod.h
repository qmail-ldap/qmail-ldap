/* auth_mod.h, jeker@n-r-g.com */
#ifndef __AUTH_MOD_H__
#define __AUTH_MOD_H__

#include "stralloc.h"

extern const unsigned int auth_port;

/* 
 * auth_init must return the 0-terminated strings login and authdata.
 * possible arguments should be parsed and the argument for auth_success
 * need to be stored if later needed.
 */
void auth_init(int, char **, stralloc *, stralloc *);

/*
 * Checks if it was a hard fail (bad password) or just a soft error 
 * (user not found). May start an other auth_module. MAY NOT return.
 */
void auth_fail(const char *, int);

/* starts the next auth_module, or what ever (argv ... ) */
void auth_success(const char *);

/*
 * Error handler, for this module, MAY NOT return.
 * auth_error MAY be called befor auth_init so it is not possible to
 * use the argument passed to auth_init in this function.
 */
void auth_error(int);

/*
 * for connection forwarding, makes the login part and returns after 
 * sending the latest command immidiatly
 */
void auth_forward(int fd, char *login, char *passwd);

/*
 * returns the default maildir if it is not defined, this is normally
 * the last argument of the execution chain.
 */
char *auth_aliasempty(void);

#endif
