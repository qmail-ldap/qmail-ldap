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
#include "qldap-debug.h"

#define QLDAP_PORT LDAP_PORT

/* system libraries for syscalls */
/* #include <unistd.h> */

/* internal functions */
static int ldap_get_userinfo(LDAP *ld, LDAPMessage *msg, userinfo *info);
static int ldap_get_extrainfo(LDAP *ld, LDAPMessage *msg, extrainfo *info);

/* internal data structures */
stralloc qldap_me = {0};				/* server name, also external visible */
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
	char	*olddir;
	int		len = 256;
	int		i = 0;
	
	if ( localdelivery != 0 )
		*localdelivery = 1; /* localdelivery is on (DEFAULT) */
	if ( cluster != 0 )
		*cluster = 0; /* clustering normaly off */
	if ( bind != 0 )
		*bind = 0; /* bind normaly off */

	/* change dir to ~qmail to read the control files, but save first 
	 * the current working directory. */
	if ( (olddir = alloc(len)) == 0 ) return -1;
	/* XXX check if this correct for all systems (BSD/Solaris) */
	while ( getcwd(olddir, len ) == 0 && errno == ERANGE && i++ < 5) {
	   	if ( alloc_re(&olddir, len, len*2) == 0 ) return -1;
		len *=2;
	}
	if ( olddir == 0 ) return -1; /* giving up, normaly 8k should be 
								   * enough for a path */
	if ( chdir(auto_qmail) == -1 ) return -1; /* chdir sets errno */
	
	if (control_rldef(&qldap_me,"control/me",0,"") == -1) return -1;
	if (!stralloc_0(&qldap_me)) return -1;
	debug(64, "init_ldap: control/me: %s\n", qldap_me.s);

	if (control_rldef(&qldap_server,"control/ldapserver",0,(char *) 0) != 1) {
		return -1; /* also here the errno should be set by control_* */
	}
	if (!stralloc_0(&qldap_server)) return -1;
	debug(64, "init_ldap: control/ldapserver: %s\n", qldap_server.s);

	if (control_rldef(&qldap_basedn,"control/ldapbasedn",0,"") == -1) return -1;
	if (!stralloc_0(&qldap_basedn)) return -1; /* also stralloc sets errno's */
	debug(64, "init_ldap: control/ldapbasedn: %s\n", qldap_basedn.s);

	if (control_rldef(&qldap_user,"control/ldaplogin",0,"") == -1) return -1;
	if (!stralloc_0(&qldap_user)) return -1;
	debug(64, "init_ldap: control/ldaplogin: %s\n", qldap_user.s);

	if (control_rldef(&qldap_password,"control/ldappassword",0,"") == -1) 
		return -1;
	if (!stralloc_0(&qldap_password)) return -1;
	debug(64, "init_ldap: control/ldappassword: %s\n", qldap_password.s);

	if (localdelivery != 0) {
		if (control_readint(localdelivery,"control/ldaplocaldelivery") == -1) 
			return -1;
		debug(64, "init_ldap: control/ldaplocaldelivery: %i\n", *localdelivery);
	}
	if (cluster != 0 ) {
		if (control_readint(cluster,"control/ldapcluster") == -1) return -1;
		debug(64, "init_ldap: control/ldapcluster: %i\n", *cluster);
	}
	if ( bind != 0 ) {
		if (control_readint(bind,"control/ldaprebind") == -1) return -1;
		debug(64, "init_ldap: control/ldaprebind: %i\n", *bind);
	}
	
	if (control_rldef(&qldap_uid,"control/ldapuid",0,"") == -1) return -1;
	if (!stralloc_0(&qldap_uid)) return -1;
	debug(64, "init_ldap: control/ldapuid: %s\n", qldap_uid.s);

	if (control_rldef(&qldap_gid,"control/ldapgid",0,"") == -1) return -1;
	if (!stralloc_0(&qldap_gid)) return -1;
	debug(64, "init_ldap: control/ldapgid: %s\n", qldap_gid.s);

	if (control_rldef(&qldap_messagestore,"control/ldapmessagestore",0,"")
		   	== -1) 
		return -1;
	if (!stralloc_0(&qldap_messagestore)) return -1;
	debug(64, "init_ldap: control/ldapmessagestore: %s\n", 
			qldap_messagestore.s);

	if ( hm != 0 ) {
		if (control_rldef(hm,"control/dirmaker",0,"") == -1) return -1;
		if (!stralloc_0(hm)) return -1;
		debug(64, "init_ldap: control/dirmaker: %s\n", hm->s);
	}

	if ( dotmode != 0 ) {
		if (control_rldef(dotmode,"control/ldapdefaultdotmode",0,
					"ldaponly") == -1) return -1;
		if (!stralloc_0(dotmode)) return -1;
	}
	
	if ( quota != 0 ) {
		if (control_rldef(quota,"control/ldapdefaultquota",0,"") == -1) 
			return -1;
		if (!stralloc_0(quota)) return -1;
	}
	
	if ( quotawarning != 0 ) {
		if (control_readfile(quotawarning,"control/quotawarning",0) == 1 ) {
			replace(quotawarning->s, quotawarning->len, '\0', '\n');
			if (!stralloc_0(quotawarning)) return -1;
		} else {
			if (!stralloc_copys(quotawarning, "") ) return -1;
		}
	}

	if ( chdir(olddir) == -1 ) return -1;

	alloc_free(olddir);
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
	char *f;
	int rc;
	int version;
	int num_entries;

	debug(128, "ldap_lookup: ");
	/* allocate the connection */
	if ( (ld = ldap_init(qldap_server.s,QLDAP_PORT)) == 0 ) {
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
		qldap_errno = LDAP_BIND;
		return -1;
	}
	debug(128, ", bind succesful\n");

	/* do the search for the login uid */
	if ( (rc = ldap_search_s(ld, qldap_basedn.s, LDAP_SCOPE_SUBTREE,
							 f, attrs, 0, &res )) != LDAP_SUCCESS ) {
		alloc_free(f); /* free f */
		debug(64, "ldap_lookup: search for %s faild (%s)\n", 
				search->filter, ldap_err2string(rc) );
		qldap_errno = LDAP_SEARCH;
		return -1;
	}
	alloc_free(f); /* free f */
	debug(128, "ldap_lookup: search for %s succeded\n", search->filter);
	
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
			free(dn);
			debug(64, "ldap_lookup: rebind with %s faild (%s)", 
					dn, ldap_err2string(rc) );
			search->bind_ok = 0;
			qldap_errno = LDAP_REBIND;
			return -1;
		}
		search->bind_ok = 1;
		debug(128, "ldap_lookup: rebind with %s succeded", dn );
	}
	if ( dn != 0 ) free(dn);

	if ( ldap_get_userinfo(ld, msg, info) == -1 ) {
		return -1; /* function sets qldap_errno */
	}
	
	if ( ldap_get_extrainfo(ld, msg, extra) == -1 ) {
		return -1; /* function sets qldap_errno */
	}

	/* ok, we finished, lets clean up and disconnect from the LDAP server */
	/* XXX we should also free msg and res */
	ldap_msgfree(msg);
	ldap_msgfree(res);
	ldap_unbind_s(ld);
	return 0;

}

static int ldap_get_userinfo(LDAP *ld, LDAPMessage *msg, userinfo *info)
/* NOTE: all default qldap_* strallocs are 0-terminated */
{
	char **vals;
	int i;
	int s;
	
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
		debug(64, "undefined but NEEDED !!!!!!!\n", vals[0]);
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
		debug(64, "undefined\n", vals[0]);
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
		debug(64, "undefined\n", vals[0]);
		info->host = 0;
	}
	ldap_value_free(vals);

	debug(64, "ldap_get_userinfo: %s: ", LDAP_MAILSTORE);
	if ( (vals = ldap_get_values(ld,msg,LDAP_MAILSTORE)) != 0 ) {
		if ( vals[0][0] != '/' ) {
			/* local path, use ldapmessagestore as prefix or return a error */
			if ( !qldap_messagestore.s || qldap_messagestore.s[0] != '/' ) {
				qldap_errno = LDAP_NEEDED;
				return -1;
			}
			if ( qldap_messagestore.s[qldap_messagestore.len - 1] != '/' ) {
				/* arrg need to add a / between the two */
				s = 1;
			} else {
				s = 0;
			}
			i = qldap_messagestore.len + s;
			i += strlen( vals[0] ); /* don't have to add 1 because qldap_mms 
									 * is 0-terminated (so 1 to long) */
			if ( (info->mms = alloc( i ) ) == 0 ) {
				qldap_errno = LDAP_ERRNO;
				return -1;
			}
			str_copy( info->host, qldap_messagestore.s );
			if ( s ) str_copy( info->mms, "/" );
			str_copy( info->mms, vals[0] );
		} else {
			i = strlen( vals[0] ) + 1;
			if ( (info->mms = alloc( i ) ) == 0 ) {
				qldap_errno = LDAP_ERRNO;
				return -1;
			}
			str_copy( info->mms, vals[0] );
		}
		debug(64, "%s\n", info->mms);
	} else {
		debug(64, "unspecified but NEEDED !!!!!\n", vals[0]);
		qldap_errno = LDAP_NEEDED;
		return -1;
	}
	ldap_value_free(vals);
	
	return 0;
}

static int ldap_get_extrainfo(LDAP *ld, LDAPMessage *msg, extrainfo *info)
/* this function moves just some pointers */
{
	int i;
	
	for ( i = 0; info[i].what != 0 ; i++ ) {
		debug(64, "ldap_get_extrainfo: %s: ", info[i].what);
		info[i].vals = ldap_get_values(ld,msg,info[i].what);
		debug(64, " %s (only the first value)\n", 
					info[i].vals?info[i].vals[0]:"nothing found");
		/* free info[i].vals with ldap_value_free(info[i].vals) */
	}
	return 0;
}

char* escape_forldap(char *toescape)
/* returns the escaped string or NULL if not succesful, string needs to
 * be freed later */
/* Under LDAP, '(', ')', '\', '*' and '\0' have to be escaped with '\'
 * NOTE: because we use just simple c-strings we do not allow a '\0' in the
 * NOTE: search string, or better we ignore it, '\0' is the end of the string */
{
	register int len;
	register char *t;
	register char *s;
	char *tmp;

	len = str_len(toescape);
	if ( ( tmp = alloc( len*2+1 ) ) == 0 ) return 0;

	s = toescape;
	t = tmp;
	
	for(;;) {
#ifndef LDAP_ESCAPE_BUG
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) 
			*t++ = '\\' ;
		*t++ = *s++;
		len--;
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) 
			*t++ = '\\' ;
		*t++ = *s++;
		len--;
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) 
			*t++ = '\\' ;
		*t++ = *s++;
		len--;
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) 
			*t++ = '\\' ;
		*t++ = *s++;
		len--;
#else
#warning __LDAP_ESCAPE_BUG__IS__ON__
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '_' ; 
		else *t++ = *s++; 
		len--;
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '_' ; 
		else *t++ = *s++; 
		len--;
#endif
	}
	*t = '\0';
	return tmp;
}

