/* qldap-errno.c */
#include "qldap-errno.h"
#include "error.h"

/* XXX TODO needs to be removed */
int qldap_errno;

const char *qldap_err_str(int enbr)
/* returns a string that corresponds to the qldap_errno */
{
	switch (enbr) {
	case OK:
		return "successful";
	case ERRNO:
		return error_str(errno);
	case FAILED:
		return "unspecified error";
	case PANIC:
		return "PANIC! Fatal error";

	case NOSUCH:
		return "no such object";
	case TOOMANY:
		return "too many objects";
	case TIMEOUT:
		return "operation timed out";

	case BADVAL:
		return "bad value";
	case ILLVAL:
		return "illegal value";
	case NEEDED:
		return "needed value is missing";

	case BADPASS:
		return "authorization failed, wrong password";
	case FORWARD:
		return "session needs to be forwarded";

	case BADCLUSTER:
		return "misconfigured cluster";
	case ACC_DISABLED:
		return "account disabled";
	case AUTH_EXEC:
		return "unable to start subprogram";
	case AUTH_CONF:
		return "configuration error";
	case AUTH_TYPE:
		return "unsupported authentication mode";

	case MAILDIR_NONEXIST:
		return "maildir/homedir does not exist";
	case MAILDIR_UNCONF:
		return "no dirmaker script configured";
	case MAILDIR_CORRUPT:
		return "maildir seems to be corrupted";
	case MAILDIR_CRASHED:
		return "dirmaker script crashed";
	case MAILDIR_FAILED:
		return "automatic maildir/homedir creation failed";
	case MAILDIR_HARD:
		return "hard error in maildir/homedir creation";
		
	case LDAP_BIND_UNREACH:
		return "ldap server down or unreachable";
	case LDAP_BIND_AUTH:
		return "wrong bind password for ldap server";
	default:
		return "unknown error occured";
	}
}

