/* qldap-ldaplib.h, jeker@n-r-g.com, best viewed with tabsize = 4 */
#ifndef __QLDAPLIB_H__
#define __QLDAPLIB_H__
#include "stralloc.h"

/* XXX this file and the corresponding .c file needs a major update */

typedef struct userinfo_t {
	int		status;
	char	*user;
	char	*uid;
	char	*gid;
	char	*mms;
	char	*homedir;
	char	*host;
} userinfo;

typedef struct extrainfo_t {
	char	*what;
	char	**vals;
} extrainfo;

typedef struct searchinfo_t {
	int			bind_ok;
	char		*bindpw;
	char		*filter;
} searchinfo;

int init_ldap(int *localdelivery, int *cluster, int *bind, stralloc *hm,
			  stralloc *dotmode, stralloc *quota, stralloc *quotawarning);
/* reads all necesary control files and makes everything ready for a ldap lookup
 * Returns 0 if successful else -1 is returned and errno is set.
 * Localdelivery is set to 0 or 1 as in ~control/ldaplocaldelivery specified.
 * Also bind and cluster are set to 0 and 1 as in their files described */

int qldap_open(void);
/* Open a connection to the ldap server */
/* XXX THIS IS A UGLY HACK */

int qldap_lookup(searchinfo *search, char **attrs, userinfo *info, 
				extrainfo *extra);
/* searches a db entry as specified in search, and fills up info and extra with
 * the coresponding db entries or NULL if not available.
 * Returns 0 if a entry was found, 1 if more than one or no corresponding entry
 * was found. On error it returns -1 and sets the appropriate qldap_errno. */

int qldap_close(void);
/* Close a established ldap connection */
/* XXX THIS IS A UGLY HACK */

int escape_forldap(stralloc *toescape);
/* Under LDAP, '(', ')', '\', '*' and '\0' have to be escaped with '\'
 * on success returns 1 else 0 */

extern void ldap_value_free();
/* LDAP function to free **vals */

#endif

