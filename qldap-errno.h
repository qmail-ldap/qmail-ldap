#ifndef __QLDAP_ERRNO_H__
#define __QLDAP_ERRNO_H__

/* XXX TODO cleanup */

extern int qldap_errno;

/* generic errors */
#define OK			0	/* all OK */
#define ERRNO			1	/* check errno for more info */
#define FAILED			2	/* generic failed message */
#define PANIC			3	/* fatal error happend */

#define NOSUCH			4	/* no such object */
#define TOOMANY			5	/* too many objects */
#define TIMEOUT			6	/* operation timed out */

#define BADVAL			7	/* bad value */
#define ILLVAL			8	/* illegal value (check failed) */
#define NEEDED			9	/* needed value is missing */

#define BADPASS			10	/* auth failed wrong password */
#define FORWARD			11	/* session needs to be forwarded */

/* auth_mod and checkpassword specific errors */
#define BADCLUSTER		20	/* bad settings for clustering */
#define ACC_DISABLED		21	/* account disabled */
#define AUTH_EXEC		22	/* unable to start subprogram */
#define AUTH_CONF		23	/* configuration error */
#define AUTH_TYPE		24	/* unsuportet auth type */

/* maildirmake specific errors */
#define MAILDIR_NONEXIST	25	/* maildir/homedir does not exist */
#define MAILDIR_UNCONF		26	/* no dirmaker script configured */
#define MAILDIR_CORRUPT		27	/* maildir seems to be corrupted */
#define MAILDIR_CRASHED		28	/* dirmaker script crashed */
#define MAILDIR_FAILED		29	/* automatic maildir creation failed */
#define MAILDIR_HARD		30	/* hard error in maildir creation */

/* LDAP specific errnos */
#define LDAP_BIND_UNREACH	31	/* ldap server down or unreachable */
#define LDAP_BIND_AUTH		32	/* wrong bind password */

const char *qldap_err_str(int enbr);
/* returns a string that corresponds to the qldap_errno */

#endif
