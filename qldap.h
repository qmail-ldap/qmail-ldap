#ifndef __QLDAP_H__
#define __QLDAP_H__

#include "stralloc.h"

#define SINGLE_VALUE	1
#define MULTI_VALUE	2
#define OLDCS_VALUE	3

#define SCOPE_BASE	0x10
#define SCOPE_ONELEVEL	0x20
#define SCOPE_SUBTREE	0x30

typedef struct qldap qldap;

int qldap_controls(void);
int qldap_need_rebind(void);
char *qldap_basedn(void);
qldap *qldap_new(void);

/* possible errors:
 * init: FAILED, ERRNO
 * bind: FAILED, LDAP_BIND_UNREACH, LDAP_BIND_AUTH
 * rebind: FAILED, ERRNO, LDAP_BIND_UNREACH, LDAP_BIND_AUTH
 */
int qldap_open(qldap *);
int qldap_bind(qldap *, const char *, const char *);
int qldap_rebind(qldap *, const char *, const char *);

/* possible errors:
 * all free functions return always OK
 */
int qldap_free_results(qldap *);
int qldap_free(qldap *);

/* possible errors:
 * FAILED TIMEOUT TOOMANY NOSUCH
 */
int qldap_lookup(qldap *, const char *, const char *[]);

/* possible errors:
 * FAILED TIMEOUT NOSUCH
 */
int qldap_filter(qldap *, const char *, const char *[], char *, int);

/*
 * returns -1 on error
 */
int qldap_count(qldap *);

/* possible errors:
 * FAILED NOSUCH (no more results)
 */
int qldap_first(qldap *);
int qldap_next(qldap *);

/* possible errors of all get functions:
 * FAILED ERRNO BADVAL ILLVAL NEEDED NOSUCH TOOMANY
 */
int qldap_get_uid(qldap *, int *);
int qldap_get_gid(qldap *, int *);
int qldap_get_mailstore(qldap *, stralloc *, stralloc *);
int qldap_get_user(qldap *, stralloc *);
int qldap_get_status(qldap *, int *);
int qldap_get_dotmode(qldap *, stralloc *);
int qldap_get_quota(qldap *, unsigned long *, unsigned long *, unsigned long *);

int qldap_get_dn(qldap *, stralloc *);
int qldap_get_ulong(qldap *, const char *, unsigned long *);
int qldap_get_bool(qldap *, const char *, int *);
int qldap_get_attr(qldap *, const char *, stralloc *, int);

/* qldap-filter.c */
char *filter_escape(char *);
char *filter_objectclass(char *);
char *filter_uid(char *);
char *filter_mail(char *, int *);
int filter_mail_ext(void);
#endif
