/* qldap-errno.c */
#include "qldap-errno.h"
#include "error.h"

int qldap_errno;

char *qldap_err_str(int enbr )
/* returns a string that corresponds to the qldap_errno */
{
	switch (enbr) {
		case ERRNO:
			return error_str(errno);
		case LDAP_INIT:
			return "initalizing of ldap connection faild";
		case LDAP_BIND:
			return "binding to ldap server faild";
		case LDAP_SEARCH:
			return "ldap_search faild";
		case LDAP_NOSUCH:
			return "no such object";
		case LDAP_REBIND:
			return "rebinding to ldap server faild";
		case LDAP_NEEDED:
			return "needed object/field is missing";
		case LDAP_COUNT:
			return "too many entries found";

		case AUTH_FAILD:
			return "authorization faild wrong password";
		case AUTH_ERROR:
			return "error on authentication";
		case ILL_PATH:
			return "illegal path";
		case ILL_AUTH:
			return "illegal authentication mode";
		case BADCLUSTER:
			return "bad settings for clustering";
		case ACC_DISABLED:
			return "account disabled";
		case AUTH_PANIC:
			return "unexpected event, PANIC";
		case AUTH_EXEC:
			return "unable to start subprogram";
			
		case MAILDIR_CORRUPT:
			return "maildir seems to be corrupted";
		case MAILDIR_CRASHED:
			return "dirmaker script crashed";
		case MAILDIR_BADEXIT:
			return "dirmaker exit status not zero";
		default:
			return "unknown error occured";
	}
}

