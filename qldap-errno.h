/* qldap-errno.h, jeker@n-r-g.com, best viewed with tabsize = 4 */
#ifndef __QLDAP_ERRNO_H__
#define __QLDAP_ERRNO_H__

extern int qldap_errno;

/* generic errors */
#define ERRNO			1				/* check errno for more info */

/* first the LDAP errnos */
#define LDAP_INIT		2				/* error while initalizing ldap connection */
#define LDAP_BIND		3				/* error while binding to ldap server */
#define LDAP_SEARCH		4				/* error on ldap search */
#define LDAP_NOSUCH		5				/* no such ldap db entry */
#define LDAP_REBIND		6				/* error while rebinding to ldap server */
#define LDAP_ERRNO		ERRNO			/* check errno for more info */
#define LDAP_NEEDED		7				/* needed db field missing */
#define LDAP_COUNT		8				/* too many entries found */

/* now the checkpassword errnos */
#define AUTH_FAILD		9				/* authorization faild wrong password */
#define AUTH_ERROR		10				/* error on authentication */
#define AUTH_NOSUCH		LDAP_NOSUCH		/* no such user */
#define ILL_PATH		11				/* illegal path */
#define ILL_AUTH		12				/* illegal authentication mode */
#define AUTH_NEEDED		LDAP_NEEDED		/* needed authentication field missing */
#define BADCLUSTER		13				/* bad settings for clustering */
#define ACC_DISABLED	14				/* account disabled */
#define AUTH_PANIC		15				/* PANIC, ARRGGG ... */
#define AUTH_EXEC		16				/* unable to start subprogram */

/* now the maildirmake errnos */
#define MAILDIR_CORRUPT	17				/* maildir seems to be corrupted */
#define MAILDIR_CRASHED	18				/* dirmaker script crashed */
#define MAILDIR_BADEXIT	19				/* dirmaker exit status not zero */

char *qldap_err_str(int enbr );
/* returns a string that corresponds to the qldap_errno */

#endif
