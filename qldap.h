#ifndef __QLDAP_H__
#define __QLDAP_H__

#include "stralloc.h"

#define SINGLE_VALUE	1
#define MULTI_VALUE	2
#define OLDCS_VALUE	3

typedef struct qldap qldap;

int qldap_controls(void);
int qldap_need_rebind(void);
qldap * qldap_new(void);

/* possible errors:
 * init: FAILED, ERRNO
 * bind: FAILED, LDAP_BIND_UNREACH, LDAP_BIND_AUTH
 * rebind: FAILED, ERRNO, LDAP_BIND_UNREACH, LDAP_BIND_AUTH
 */
int qldap_open(qldap *);
int qldap_bind(qldap *, char *, char *);
int qldap_rebind(qldap *, char *, char *);

/* possible errors:
 * all free functions return always OK
 */
int qldap_free_results(qldap *);
int qldap_free(qldap *);

/* possible errors:
 * FAILED TIMEOUT TOOMANY NOSUCH
 */
int qldap_lookup(qldap *, char *, const char *[]);

/* possible errors of all get functions:
 * FAILED ERRNO BADVAL ILLVAL NEEDED NOSUCH TOOMANY
 */
int qldap_get_uid(qldap *, int *);
int qldap_get_gid(qldap *, int *);
int qldap_get_mailstore(qldap *, stralloc *, stralloc *);
int qldap_get_user(qldap *, stralloc *);
int qldap_get_status(qldap *, int *);
int qldap_get_dotmode(qldap *, stralloc *);
int qldap_get_quota(qldap *, stralloc *, unsigned long *);

int qldap_get_dn(qldap *, stralloc *);
int qldap_get_attr(qldap *, const char *, stralloc *, int);

char *ldap_escape(char *);
char *ldap_ocfilter(char *);

#endif
