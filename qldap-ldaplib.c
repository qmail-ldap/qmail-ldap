/* qldap-ldaplib.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "qmail-ldap.h"
#include "qldap-errno.h"
#include <lber.h>
#include <ldap.h>
#include "qldap-ldaplib.h"
#include "alloc.h"
#include "stralloc.h"
#include "error.h"
#include <errno.h> /* for ERANGE et al. */
#include "control.h"
#include "auto_qmail.h"
#include "str.h"
#include "byte.h"
#include "qldap-debug.h"
#include "fmt.h"

#define QLDAP_PORT LDAP_PORT
#ifndef PORT_LDAP /* this is for testing purposes, so you can overwrite 
					 this port via a simple -D argument */
#define PORT_LDAP QLDAP_PORT
#endif

/* system libraries for syscalls */
/* #include <unistd.h> */

/* internal functions */
static int ldap_get_userinfo(LDAP *ld, LDAPMessage *msg, userinfo *info);
static int ldap_get_extrainfo(LDAP *ld, LDAPMessage *msg, extrainfo *info);

/* internal data structures */
stralloc qldap_me = {0};				/* server name, also external visible */
stralloc qldap_objectclass = {0};		/* the search objectclass, external visible */

/* internal use only vars */
static stralloc qldap_server = {0};		/* name of ldap server */
static stralloc qldap_basedn = {0};		/* the search basedn */
static stralloc qldap_user = {0};		/* the ldap user ( for login ) */
static stralloc qldap_password = {0};	/* the ldap login password */

static stralloc qldap_uid = {0};		/* UID if not specified in db */
static stralloc qldap_gid = {0};		/* UID if not specified in db */
static stralloc qldap_messagestore = {0}; /* perfix for maildirpaths */


/* char replacement */
static unsigned int replace(char *s, register unsigned int len, char f, char r)
{
   register char *t;
   register int count = 0;

   t=s;
   for(;;) {
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
   }
}

int init_ldap(int *localdelivery, int *cluster, int *bind, stralloc *hm,
			  stralloc *dotmode, stralloc *quota, stralloc *quotawarning)
/* reads all necesary control files and makes everything ready for a ldap lookup
 * Returns 0 if successful else -1 is returned and errno is set.
 * Localdelivery is set to 0 or 1 as in ~control/ldaplocaldelivery specified.
 * Also bind and cluster are set to 0 and 1 as in their files described */
{
	char	*ctrl_file;
	char	*cf;
	char	*t;

	if ( localdelivery != 0 )
		*localdelivery = 1; /* localdelivery is on (DEFAULT) */
	if ( cluster != 0 )
		*cluster = 0; /* clustering normaly off */
	if ( bind != 0 )
		*bind = 0; /* bind normaly off */

	if ( ! (ctrl_file = alloc(64 + str_len(auto_qmail) + 2 ) )) return -1;
	/* XXX 64 char should be enough to handle all ~control/ files */
	cf = ctrl_file;
	cf += fmt_str(cf, auto_qmail);
	*cf++ = '/';
	t = cf;
	t += fmt_strn(cf, "control/me", 64); *t=0;
	if (control_rldef(&qldap_me, ctrl_file, 0, "") == -1) return -1;
	if (!stralloc_0(&qldap_me)) return -1;
	debug(64, "init_ldap: control/me: %s\n", qldap_me.s);

	t = cf;
	t += fmt_strn(cf, "control/ldapserver", 64); *t=0;
	if (control_rldef(&qldap_server, ctrl_file, 0, (char *) 0) != 1) {
		return -1; /* also here the errno should be set by control_* */
	}
	if (!stralloc_0(&qldap_server)) return -1;
	debug(64, "init_ldap: control/ldapserver: %s\n", qldap_server.s);

	t = cf;
	t += fmt_strn(cf, "control/ldapbasedn", 64); *t=0;
	if (control_rldef(&qldap_basedn, ctrl_file, 0, "") == -1) return -1;
	if (!stralloc_0(&qldap_basedn)) return -1; /* also stralloc sets errno's */
	debug(64, "init_ldap: control/ldapbasedn: %s\n", qldap_basedn.s);

	t = cf;
	t += fmt_strn(cf, "control/ldapobjectclass", 64); *t=0;
	if (control_rldef(&qldap_objectclass, ctrl_file, 0, "") == -1) return -1;
	debug(64, "init_ldap: control/ldapobjectclass: %S\n", &qldap_objectclass);

	t = cf;
	t += fmt_strn(cf, "control/ldaplogin", 64); *t=0;
	if (control_rldef(&qldap_user, ctrl_file, 0, "") == -1) return -1;
	if (!stralloc_0(&qldap_user)) return -1;
	debug(64, "init_ldap: control/ldaplogin: %s\n", qldap_user.s);

	t = cf;
	t += fmt_strn(cf, "control/ldappassword", 64); *t=0;
	if (control_rldef(&qldap_password, ctrl_file, 0, "") == -1) 
		return -1;
	if (!stralloc_0(&qldap_password)) return -1;
	debug(64, "init_ldap: control/ldappassword: %s\n", qldap_password.s);

	t = cf;
	t += fmt_strn(cf, "control/ldapuid", 64); *t=0;
	if (control_rldef(&qldap_uid, ctrl_file, 0, "") == -1) return -1;
	if (!stralloc_0(&qldap_uid)) return -1;
	debug(64, "init_ldap: control/ldapuid: %s\n", qldap_uid.s);

	t = cf;
	t += fmt_strn(cf, "control/ldapgid", 64); *t=0;
	if (control_rldef(&qldap_gid, ctrl_file, 0, "") == -1) return -1;
	if (!stralloc_0(&qldap_gid)) return -1;
	debug(64, "init_ldap: control/ldapgid: %s\n", qldap_gid.s);

	t = cf;
	t += fmt_strn(cf, "control/ldapmessagestore", 64); *t=0;
	if (control_rldef(&qldap_messagestore, ctrl_file, 0, "") == -1) 
		return -1;
	if (!stralloc_0(&qldap_messagestore)) return -1;
	debug(64, "init_ldap: control/ldapmessagestore: %s\n", 
			qldap_messagestore.s);

	if (localdelivery != 0) {
		t = cf;
		t += fmt_strn(cf, "control/ldaplocaldelivery", 64); *t=0;
		if (control_readint(localdelivery, ctrl_file) == -1) 
			return -1;
		debug(64, "init_ldap: control/ldaplocaldelivery: %i\n", *localdelivery);
	}
	if (cluster != 0 ) {
		t = cf;
		t += fmt_strn(cf, "control/ldapcluster", 64); *t=0;
		if (control_readint(cluster, ctrl_file) == -1) return -1;
		debug(64, "init_ldap: control/ldapcluster: %i\n", *cluster);
	}
	if ( bind != 0 ) {
		t = cf;
		t += fmt_strn(cf, "control/ldaprebind", 64); *t=0;
		if (control_readint(bind, ctrl_file) == -1) return -1;
		debug(64, "init_ldap: control/ldaprebind: %i\n", *bind);
	}

	if ( hm != 0 ) {
		t = cf;
		t += fmt_strn(cf, "control/dirmaker", 64); *t=0;
		if (control_rldef(hm, ctrl_file, 0, "") == -1) return -1;
		if (!stralloc_0(hm)) return -1;
		debug(64, "init_ldap: control/dirmaker: %s\n", hm->s);
	}

	if ( dotmode != 0 ) {
		t = cf;
		t += fmt_strn(cf, "control/ldapdefaultdotmode", 64); *t=0;
		if (control_rldef(dotmode, ctrl_file, 0, "ldaponly") == -1) return -1;
		if (!stralloc_0(dotmode)) return -1;
	}

	if ( quota != 0 ) {
		t = cf;
		t += fmt_strn(cf, "control/ldapdefaultquota", 64); *t=0;
		if (control_rldef(quota, ctrl_file, 0, "") == -1) 
			return -1;
		if (!stralloc_0(quota)) return -1;
	}

	if ( quotawarning != 0 ) {
		t = cf;
		t += fmt_strn(cf, "control/quotawarning", 64); *t=0;
		if (control_readfile(quotawarning, ctrl_file, 0) == 1 ) {
			replace(quotawarning->s, quotawarning->len, '\0', '\n');
			if (!stralloc_0(quotawarning)) return -1;
		} else {
			if (!stralloc_copys(quotawarning, "") ) return -1;
		}
	}

	alloc_free(ctrl_file);
	return 0;
}

int ldap_lookup(searchinfo *search, char **attrs, userinfo *info, 
				extrainfo *extra)
/* searches a db entry as specified in search, and fills up info and extra with
 * the coresponding db entries or NULL if not available.
 * Returns 0 if a entry was found, 1 if more than one or no corresponding entry
 * was found. On error it returns -1 and sets the appropriate qldap_errno. */
{
	LDAP *ld;
	LDAPMessage *res, *msg;
	char *dn;
	int rc;
	int version;
	int num_entries;

#ifndef USE_CLDAP
	debug(128, "ldap_lookup: ");
	/* allocate the connection */
	if ( (ld = ldap_init(qldap_server.s,PORT_LDAP)) == 0 ) {
		qldap_errno = LDAP_INIT;
		return -1;
	}
	debug(128, "init succesful");

#ifdef LDAP_OPT_PROTOCOL_VERSION
	/* set LDAP connection options (only with Mozilla LDAP SDK) */
	version = LDAP_VERSION2;
	if ( ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)
		   	!= LDAP_SUCCESS ) {
		qldap_errno = LDAP_INIT;
		return -1;
	}
	debug(128, ", set_option succesful");
#endif

	/* connect to the LDAP server */
	if ( (rc = ldap_simple_bind_s(ld,qldap_user.s,qldap_password.s)) 
			!= LDAP_SUCCESS ) {
		debug(128, ", bind NOT succesful (%s)\n", ldap_err2string(rc) );

		/* probably more detailed information should be returned, eg.:
		   LDAP_STRONG_AUTH_NOT_SUPPORTED,
		   LDAP_STRONG_AUTH_REQUIRED,
		   *LDAP_INAPPROPRIATE_AUTH*,
		   *LDAP_INVALID_CREDENTIALS*,
		   LDAP_AUTH_UNKNOWN
		*/
		if (rc == LDAP_SERVER_DOWN) {
			qldap_errno = LDAP_BIND_UNREACH;
			return -1;
		}
		else {
			qldap_errno = LDAP_BIND;
			return -1;
		}
	}
	debug(128, ", bind succesful\n");

	/* do the search for the login uid */
	if ( (rc = ldap_search_s(ld, qldap_basedn.s, LDAP_SCOPE_SUBTREE,
							 search->filter, attrs, 0, &res )) != LDAP_SUCCESS ) {
		debug(64, "ldap_lookup: search for %s failed (%s)\n", 
				search->filter, ldap_err2string(rc) );

		/* probably more detailed information should be returned, eg.:
		   LDAP_TIMELIMIT_EXCEEDED,
		   LDAP_SIZELIMIT_EXCEEDED,
		   LDAP_PARTIAL_RESULTS,
		   LDAP_INSUFFICIENT_ACCESS,
		   LDAP_BUSY,
		   LDAP_UNAVAILABLE,
		   LDAP_UNWILLING_TO_PERFORM,
		   LDAP_TIMEOUT
		*/
		qldap_errno = LDAP_SEARCH;
		return -1;
	}
#else /* USE_CLDAP */
	debug(128, "ldap_lookup: ");
	/* allocate the connection */
	if ( (ld = cldap_open(qldap_server.s,PORT_LDAP)) == 0 ) {
		qldap_errno = LDAP_INIT;
		return -1;
	}
	debug(128, "cldap_open succesful\n");
	/* do the search for the login uid */
	if ( (rc = cldap_search_s(ld, qldap_basedn.s, LDAP_SCOPE_SUBTREE,
					search->filter, attrs, 0, &res, qldap_user.s )) 
					!= LDAP_SUCCESS )
	{
		debug(64, "ldap_lookup: csearch for %s failed (%s)\n",
				search->filter, ldap_err2string(rc) );
		qldap_errno = LDAP_SEARCH;
		return -1;
	}
#endif

	debug(128, "ldap_lookup: search for %s succeeded\n", search->filter);
	
	/* go to the first entry */
	msg = ldap_first_entry(ld,res);

	/* count the results, we must have exactly one */
	if ( (num_entries = ldap_count_entries(ld,msg)) != 1) {
		debug(64, "ldap_lookup: Too many (less) entries found (%i)\n", 
				num_entries);
		if ( num_entries )
			qldap_errno = LDAP_COUNT;
		else
			qldap_errno = LDAP_NOSUCH;
		return -1;
	}
	
	/* get the dn and free it (we dont need it, to prevent memory leaks)
	 * but first try to rebind with the password */
	dn = ldap_get_dn(ld,msg);
	if ( search->bindpw ) {
		if ( dn == 0 ) {
			qldap_errno = LDAP_REBIND;
			return -1;
		}
		/* do re-bind here */
		if ( (rc = ldap_simple_bind_s(ld,dn,search->bindpw)) != LDAP_SUCCESS) {
			alloc_free(dn);
			debug(64, "ldap_lookup: rebind with %s failed (%s)", 
					dn, ldap_err2string(rc) );
			search->bind_ok = 0;
			qldap_errno = LDAP_REBIND;
			return -1;
		}
		search->bind_ok = 1;
		debug(128, "ldap_lookup: rebind with %s succeeded", dn );
	}
	if ( dn != 0 ) alloc_free(dn);

	if ( ldap_get_userinfo(ld, msg, info) == -1 ) {
		return -1; /* function sets qldap_errno */
	}
	
	if ( ldap_get_extrainfo(ld, msg, extra) == -1 ) {
		return -1; /* function sets qldap_errno */
	}

	/* ok, we finished, lets clean up and disconnect from the LDAP server */
	/* XXX we should also free msg and res */
	/* ldap_msgfree(msg); */ /* with this I get segv's :-( don't ask me why */
	ldap_msgfree(res);
#ifndef USE_CLDAP
	ldap_unbind_s(ld);
#else /* USE_CLDAP */
	cldap_close(ld);
#endif
	return 0;

}

static int ldap_get_mms(char **mmsval, char **hdval, char **mms, char **homedir);

static int ldap_get_userinfo(LDAP *ld, LDAPMessage *msg, userinfo *info)
/* NOTE: all default qldap_* strallocs are 0-terminated */
/* Thanks to Tony Abbott for the bug fixes */
{
	char **vals;
	char **vals2;
	int i;
	
	if (! info ) return 0;
	/* get those entries LDAP_QMAILUID, LDAP_QMAILGID, LDAP_MAILSTORE, 
	 * LDAP_MAILHOST, LDAP_ISACTIVE and LDAP_UID */
	debug(64, "ldap_get_userinfo: %s: ", LDAP_QMAILUID);
	if ( (vals = ldap_get_values(ld,msg,LDAP_QMAILUID)) != 0 ) {
		if ( (info->uid = alloc( str_len( vals[0] ) + 1 ) ) == 0 ) {
			qldap_errno = LDAP_ERRNO;
			return -1;
		}
		debug(64, "%s (from server)\n", vals[0]);
		str_copy( info->uid, vals[0] );
	} else {
		if (!( qldap_uid.s && qldap_uid.s[0] ) ) {
			debug(64, "undefined\n");
			qldap_errno = LDAP_NEEDED;
			return -1;
		}
		if ( (info->uid = alloc( qldap_uid.len ) ) == 0 ) {
			qldap_errno = LDAP_ERRNO;
			return -1;
		}
		debug(64, "%s (default)\n", qldap_uid.s);
		str_copy( info->uid, qldap_uid.s );
	}
	ldap_value_free(vals);

	debug(64, "ldap_get_userinfo: %s: ", LDAP_QMAILGID);
	if ( (vals = ldap_get_values(ld,msg,LDAP_QMAILGID)) != 0 ) {
		if ( (info->gid = alloc( str_len( vals[0] ) + 1 ) ) == 0 ) {
			qldap_errno = LDAP_ERRNO;
			return -1;
		}
		debug(64, "%s (from server)\n", vals[0]);
		str_copy( info->gid, vals[0] );
	} else {
		if (!( qldap_gid.s && qldap_gid.s[0] ) ) {
			debug(64, "undefined\n");
			qldap_errno = LDAP_NEEDED;
			return -1;
		}
		if ( (info->gid = alloc( qldap_gid.len ) ) == 0 ) {
			qldap_errno = LDAP_ERRNO;
			return -1;
		}
		debug(64, "%s (default)\n", qldap_uid.s);
		str_copy( info->gid, qldap_gid.s );
	}
	ldap_value_free(vals);

	/* get the username for delivery on the local system */
	debug(64, "ldap_get_userinfo: %s: ", LDAP_UID);
	if ( (vals = ldap_get_values(ld,msg,LDAP_UID)) != 0 ) {
		if ( (info->user = alloc( str_len( vals[0] ) + 1 ) ) == 0 ) {
			qldap_errno = LDAP_ERRNO;
			return -1;
		}
		debug(64, "%s (from server)\n", vals[0]);
		str_copy( info->user, vals[0] );
	} else {
		debug(64, "undefined but NEEDED !!!!!!!\n");
		qldap_errno = LDAP_NEEDED;
		return -1;
	}
	ldap_value_free(vals);

	/* check if the ldap entry is active */
	debug(64, "ldap_get_userinfo: %s: ", LDAP_ISACTIVE);
	if ( (vals = ldap_get_values(ld,msg,LDAP_ISACTIVE)) != 0 ) {
		debug(64, "%s (from server)\n", vals[0]);
		if ( !str_diff(ISACTIVE_BOUNCE, vals[0]) ) 
			info->status = STATUS_BOUNCE;
		else if ( !str_diff(ISACTIVE_NOPOP, vals[0]) ) 
			info->status = STATUS_NOPOP;
		else info->status = STATUS_OK;
	} else {
		debug(64, "undefined\n");
		info->status = STATUS_UNDEF;
	}
	ldap_value_free(vals);

	debug(64, "ldap_get_userinfo: %s: ", LDAP_MAILHOST);
	if ( (vals = ldap_get_values(ld,msg,LDAP_MAILHOST)) != 0 ) {
		if ( (info->host = alloc( str_len( vals[0] ) + 1 ) ) == 0 ) {
			qldap_errno = LDAP_ERRNO;
			return -1;
		}
		debug(64, "%s (from server)\n", vals[0]);
		str_copy( info->host, vals[0] );
	} else {
		debug(64, "undefined\n");
		info->host = 0;
	}
	ldap_value_free(vals);

	debug(64, "ldap_get_userinfo: %s & %s: \n", LDAP_MAILSTORE, LDAP_HOMEDIR);
	vals = ldap_get_values(ld,msg,LDAP_MAILSTORE);
	vals2 = ldap_get_values(ld,msg,LDAP_HOMEDIR);
	i = ldap_get_mms(vals, vals2, &(info->mms), &(info->homedir));  
	debug(64, "%s=%s & %s=%s\n", LDAP_HOMEDIR, info->homedir, 
			LDAP_MAILSTORE, info->mms);
	ldap_value_free(vals);
	ldap_value_free(vals2);
	if ( i == -1 ) {
		/* ldap_get_mms sets qldap_errno */
		return -1;
	}
	return 0;
}

static int ldap_get_extrainfo(LDAP *ld, LDAPMessage *msg, extrainfo *info)
/* this function moves just some pointers */
{
	int i;
	
	if (! info ) return 0;
	for ( i = 0; info[i].what != 0 ; i++ ) {
		debug(64, "ldap_get_extrainfo: %s: ", info[i].what);
		info[i].vals = ldap_get_values(ld,msg,info[i].what);
		debug(64, " %s\n", 
					info[i].vals?info[i].vals[0]:"nothing found");
		/* free info[i].vals with ldap_value_free(info[i].vals) */
	}
	return 0;
}

static int ldap_get_mms(char **mmsval, char **hdval, char **mms, char **homedir)
{
	int i;
	int s;

	if ( hdval ) {
		if ( hdval[0][0] != '/' ) {
			debug(64, "non absolute homedirectory path!\n");
			qldap_errno = LDAP_NEEDED;
			return -1;
		}
		if ( (*homedir = alloc( str_len( hdval[0] ) + 1 ) ) == 0 ) {
			qldap_errno = LDAP_ERRNO;
			return -1;
		}
		debug(64, "%s=%s (from server)\n", LDAP_HOMEDIR, hdval[0]);
		str_copy( *homedir, hdval[0] );
	} else {
		debug(64, "%s=undefined\n", LDAP_HOMEDIR);
		*homedir = 0;
	}
	if ( mmsval ) {
		debug(64, "%s=%s (from server)\n", LDAP_MAILSTORE, mmsval[0]);
		if ( mmsval[0][0] != '/' ) {
			/* local path, use ldapmessagestore as prefix or return a error */
			if ( (!qldap_messagestore.s || qldap_messagestore.s[0] != '/') 
					&& *homedir == 0 ) {
				debug(64, "non absolute path but neither ctrl/ldapmessagestore nor homedir defined!\n");
				qldap_errno = LDAP_NEEDED;
				return -1;
			}
			i = 0; s = -1;
			if ( *homedir == 0 ) {
				debug(64, " using %s as prefix\n", qldap_messagestore.s);
				/* XXX if both homedir and ldapmms are defined homedir has 
				 * higher priority (ldapmms will be ignored (not prefixed ) ) */
				if ( qldap_messagestore.s[qldap_messagestore.len - 1] != '/' ) {
					/* arrg need to add a / between the two */
					s = 0;
				}
				i = qldap_messagestore.len + s;
				/* qldap_mms is one char too long so reduce the length */
			}
			i += str_len( mmsval[0] ) + 1; 
			if ( (*mms = alloc( i ) ) == 0 ) {
				qldap_errno = LDAP_ERRNO;
				return -1;
			}
			if ( *homedir == 0) { 
				str_copy( *mms, qldap_messagestore.s );
				if ( s == 0 ) str_copy( *mms + str_len(*mms), "/" );
				/* str_cat done with str_copy because djb has no str_cat :-( */
				str_copy( *mms + str_len(*mms), mmsval[0] );
			} else {
				str_copy( *mms, mmsval[0] );
			}
		} else {
			i = str_len( mmsval[0] ) + 1;
			if ( (*mms = alloc( i ) ) == 0 ) {
				qldap_errno = LDAP_ERRNO;
				return -1;
			}
			str_copy( *mms, mmsval[0] );
		}
	} else {
		debug(64, "%s=undefined\n", LDAP_MAILSTORE);
		*mms = 0;
	}
	return 0;
}

int escape_forldap(stralloc *toescape)
/* Under LDAP, '(', ')', '\', '*' and '\0' have to be escaped with '\' */
{
	unsigned int len;
	unsigned int newlen;
	char x;
	char *t;
	char *s;
	char *tmp;

	newlen = 0;
	len = toescape->len;
	s = toescape->s;

	if ( s[len-1] == '\0' ) len-- ; /* this handles \0 terminated strallocs */

	if ( ( tmp = alloc( len*2 ) ) == 0 ) return 0;
	t = tmp;
	
	for(;;) {
#ifndef LDAP_ESCAPE_BUG
		if(!len) break; 
		x = *s;
		if (x == '*' || x == '(' || x == ')' || x == '\\' || x == '\0' ) {
			*t++ = '\\' ; newlen++;
		}
		*t++ = *s++;
		len--; newlen++;
#else
#warning __LDAP_ESCAPE_BUG__IS__ON__
		if(!len) break; 
		x = *s;
		if (x == '*' || x == '(' || x == ')' || x == '\\' || x == '\0' ) 
			*t++ = '_' ; 
		else *t++ = *s++; 
		len--; newlen++;
#endif
	}
	if (!stralloc_ready(toescape, newlen) ) return 0;
	toescape->len = newlen;
	byte_copy(toescape->s, newlen, tmp);
	alloc_free(tmp);
	return 1;
}

