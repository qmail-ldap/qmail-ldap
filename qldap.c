#include <sys/time.h> /* for ldap search timeout */

#include <lber.h>
#include <ldap.h>

#include "alloc.h"
#include "byte.h"
#include "case.h"
#include "check.h"
#include "control.h"
#include "error.h"
#include "fmt.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "scan.h"
#include "str.h"
#include "stralloc.h"

#include "qldap.h"

struct qldap {
	int		state;
#define NEW	0
#define OPEN	1
#define BIND	2
#define SEARCH	3
#define EXTRACT	4
#define REBIND	5
#define CLOSE	6
#define ERROR	-1
	LDAP		*ld;
	LDAPMessage	*res; /* valid after a search */
	LDAPMessage	*msg; /* valid after call to ldap_first_entry() */
	/* should we store server, binddn, basedn, password, ... */
};

/* TODO definition of global vars */
stralloc	ldap_server = {0};
stralloc	basedn = {0};
stralloc	objectclass = {0};
stralloc	ldap_login = {0};
stralloc	ldap_password = {0};
int		ldap_timeout = QLDAP_TIMEOUT;	/* default timeout is 30 secs */
int		rebind = 0;			/* default off */
int		default_uid;
int		default_gid;
stralloc	default_messagestore = {0};
stralloc	dotmode = {0};
unsigned long	quotasize = 0;
unsigned long	quotacount = 0;


static  int qldap_close(qldap *);

static int qldap_set_option(qldap *, int);
static int check_next_state(qldap *, int);

#define STATEIN(x, y)	((x)->state == (y))
#define CHECK(x, y)							\
	do {								\
		if (check_next_state((x), (y)) == 0) {			\
			log(128, "qldap: bad state transition");	\
			(x)->state = ERROR;				\
			return FAILED;					\
		}							\
	} while (0)


int
qldap_controls(void)
{
	/* read following files
	     ldapserver
	     ldapbasedn
	     ldapobjectclass
	     ldaplogin
	     ldappassword
	     ldapuid
	     ldapgid
	     ldapmessagestore
	     ldaptimeout
	     ldaprebind
	     ldapdefaultdotmode ???
	     ldapdefaultquota
	 */
	if (control_rldef(&ldap_server, "control/ldapserver", 0,
		    (char *) 0) != 1)
		return -1; /* ... the errno should be set by control_* */
	if (!stralloc_0(&ldap_server)) return -1;
	log(64, "init_ldap: control/ldapserver: %s\n", ldap_server.s);

	if (control_rldef(&basedn, "control/ldapbasedn", 0, "") == -1)
		return -1;
	if (!stralloc_0(&basedn)) return -1;
	log(64, "init_ldap: control/ldapbasedn: %s\n", basedn.s);

	if (control_readline(&objectclass, "control/ldapobjectclass") == -1)
		return -1;
	log(64, "init_ldap: control/ldapobjectclass: %S\n", &objectclass);

	if (control_rldef(&ldap_login, "control/ldaplogin", 0, "") == -1)
		return -1;
	if (!stralloc_0(&ldap_login)) return -1;
	log(64, "init_ldap: control/ldaplogin: %s\n", ldap_login.s);

	if (control_rldef(&ldap_password, "control/ldappassword", 0, "") == -1)
		return -1;
	if (!stralloc_0(&ldap_password)) return -1;
	log(64, "init_ldap: control/ldappassword: %s\n", ldap_password.s);

	if (control_readint(&ldap_timeout, "control/ldaptimeout") == -1)
		return -1;
	log(64, "init_ldap: control/ldaptimeout: %i\n", ldap_timeout);

	if (control_readint(&rebind, "control/ldaprebind") == -1) return -1;
	log(64, "init_ldap: control/ldaprebind: %i\n", rebind);

	
	/* defaults */
	if (control_readint(&default_uid, "control/ldapuid") == -1)
		return -1;
	if (default_uid != 0)
		log(64, "init_ldap: control/ldapuid: %i\n", default_uid);

	if (control_readint(&default_gid, "control/ldapgid") == -1)
		return -1;
	if (default_gid != 0)
		log(64, "init_ldap: control/ldapgid: %i\n", default_gid);

	if (control_rldef(&default_messagestore,
		    "control/ldapmessagestore", 0, "") == -1)
		return -1;
	if (default_messagestore.len > 1) {
		if (default_messagestore.s[default_messagestore.len-1] != '/')
			if (!stralloc_append(&default_messagestore, "/"))
				return -1;
		log(64, "init_ldap: control/ldapmessagestore: %S\n", 
		    default_messagestore);
	} else
		if (!stralloc_copys(&default_messagestore, "")) return -1;

	if (control_rldef(&dotmode, "control/ldapdefaultdotmode",
		    0, "ldaponly") == -1) return -1;
	if (!stralloc_0(&dotmode)) return -1;
	log(64, "init_ldap: control/ldapdefaultdotmode: %s\n", dotmode.s);

	if (control_readulong(&quotasize, "control/defaultquotasize") == -1) 
		return -1;
	if (control_readulong(&quotacount, "control/defaultquotacount") == -1) 
		return -1;
	log(64, "init_ldap: control/defaultquotasize: %lu\n", quotasize);
	log(64, "init_ldap: control/defaultquotacount: %lu\n", quotacount);

	return 0;
}

int
qldap_need_rebind(void)
{
	return rebind;
}

char *
qldap_basedn(void)
{
	return basedn.s;
}

qldap *
qldap_new(void)
{
	qldap *q;

	q = (qldap *)alloc(sizeof(qldap));
	if (q == 0) return (qldap *)0;
	byte_zero(q, sizeof(qldap));
	return q;
}

/******  LDAP OPEN, BIND & CLOSE  *********************************************/

int
qldap_open(qldap *q)
{
	int rc;

	CHECK(q, OPEN);
	
	log(128, "qldap_open: ");
	/* allocate the connection */
	if ((q->ld = ldap_init(ldap_server.s,LDAP_PORT)) == 0) {
		log(128, "init failed\n");
		return ERRNO;
	}
	log(128, "init successful\n");

	rc = qldap_set_option(q, 0);
	q->state = rc==OK?OPEN:ERROR;
	return rc;
}

int
qldap_bind(qldap *q, const char *binddn, const char *passwd)
{
	int rc, try = 0;
	
	CHECK(q, BIND);

	/* bind or rebind to the server with credentials */
	if (binddn == (char *)0) {
		/* use default credentials */
		binddn = ldap_login.s;
		passwd = ldap_password.s;
	}

retry:
	/* connect to the LDAP server */
	rc = ldap_simple_bind_s(q->ld, binddn, passwd);
	try++;
	/* probably more detailed information should be returned, eg.:
	   LDAP_STRONG_AUTH_NOT_SUPPORTED,
	   LDAP_STRONG_AUTH_REQUIRED,
	   *LDAP_INAPPROPRIATE_AUTH*,
	   *LDAP_INVALID_CREDENTIALS*,
	   LDAP_AUTH_UNKNOWN
	 */
	log(128, "qldap_bind: ");
	switch (rc) {
	case LDAP_SUCCESS:
		log(128, "successful\n");
		q->state = BIND;
		return OK;
	case LDAP_TIMELIMIT_EXCEEDED:
	case LDAP_SERVER_DOWN:
		log(128, "failed (%s)\n", ldap_err2string(rc) );
		q->state = ERROR;
		return LDAP_BIND_UNREACH;
	case LDAP_INVALID_CREDENTIALS:
		log(128, "failed (%s)\n", ldap_err2string(rc) );
		q->state = ERROR;
		return LDAP_BIND_AUTH;
	case LDAP_PROTOCOL_ERROR:
		log(128, "failed (%s)\n", ldap_err2string(rc) );
		/* bind failed try Version 2 */
		if (try > 1) break;
		qldap_close(q);
		rc = qldap_open(q);
		qldap_set_option(q, 1);
		if (rc != OK) break;
		goto retry;
	default:
		log(128, "failed (%s)\n", ldap_err2string(rc) );
		break;
	}
	q->state = ERROR;
	return FAILED;
}

int
qldap_rebind(qldap *q, const char *binddn, const char *passwd)
{
	int rc;

	CHECK(q, REBIND);

	if (!STATEIN(q, OPEN)) {
		qldap_close(q);
		rc = qldap_open(q);
		if (rc != OK) return rc;
	}
	return qldap_bind(q, binddn, passwd);
}

static  int
qldap_close(qldap *q)
{
	CHECK(q, CLOSE);
	
	qldap_free_results(q); /* free results */
	/* close and free ldap connection */
	ldap_unbind_s(q->ld);
	q->state = CLOSE;
	return OK;
}

int
qldap_free_results(qldap *q)
{
	if (STATEIN(q, SEARCH) || STATEIN(q, EXTRACT)) {
		ldap_msgfree(q->res);
		q->res = (LDAPMessage *)0;
		q->msg = (LDAPMessage *)0;
	}
	return OK;
}

int
qldap_free(qldap *q)
{
	if (!STATEIN(q, NEW))
		qldap_close(q);
	/* TODO free all other values and free q */
	byte_zero(q, sizeof(qldap));
	alloc_free(q);
	return OK;
}

/******  LDAP SEARCH & FILTER  ************************************************/

int
qldap_lookup(qldap *q, const char *filter, const char *attrs[])
{
	/* search a unique entry */
	struct	timeval tv;
	int	rc, num_entries;
	
	CHECK(q, SEARCH);
	
	tv.tv_sec = ldap_timeout;
	tv.tv_usec = 0;

	rc = ldap_search_st(q->ld, basedn.s, LDAP_SCOPE_SUBTREE,
		filter, attrs, 0, &tv, &q->res);
	
	switch (rc) {
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

	case LDAP_SUCCESS:
		log(128, "qldap_lookup: search for %s succeeded\n",
		    filter);
		break;
	case LDAP_TIMEOUT:
	case LDAP_TIMELIMIT_EXCEEDED:
	case LDAP_BUSY:
		log(64, "qldap_lookup: search for %s failed (%s)\n", 
		    filter, ldap_err2string(rc) );
		return TIMEOUT;
	case LDAP_NO_SUCH_OBJECT:
		log(64, "qldap_filter: search for %s failed (%s)\n", 
		    filter, ldap_err2string(rc) );
		return NOSUCH;
	default:
		log(64, "qldap_lookup: search for %s failed (%s)\n", 
		    filter, ldap_err2string(rc) );
		return FAILED;
	}

	/* count the results, we must have exactly one */
	num_entries = ldap_count_entries(q->ld, q->res);
	if (num_entries != 1) {
		if (num_entries > 1) {
			log(64, "qldap_lookup: Too many entries found (%i)\n", 
			    num_entries);
			return TOOMANY;
		} else {
			log(64, "qldap_lookup: Nothing found\n"); 
			return NOSUCH;
		}
	}
	/* go to the first entry */
	q->msg = ldap_first_entry(q->ld, q->res);
	
	/*
	 * We already selected the first and only entry so
	 * skip SEARCH state and move directly to EXTRACT state.
	 */
	q->state = EXTRACT;
	return OK;
}

int
qldap_filter(qldap *q, const char *filter, const char *attrs[],
    char *bdn, int scope)
{
	
	/* search a unique entry */
	struct	timeval tv;
	int	rc;
	
	/* search multiple entries */
	CHECK(q, SEARCH);
	
	switch (scope) {
	case SCOPE_BASE:
		scope = LDAP_SCOPE_BASE;
		break;
	case SCOPE_ONELEVEL:
		scope = LDAP_SCOPE_ONELEVEL;
		break;
	case SCOPE_SUBTREE:
		scope = LDAP_SCOPE_SUBTREE;
		break;
	default:
		return FAILED;
	}

	tv.tv_sec = ldap_timeout;
	tv.tv_usec = 0;

	rc = ldap_search_st(q->ld, bdn, scope, filter,
	    attrs, 0, &tv, &q->res);
	
	switch (rc) {
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

	case LDAP_SUCCESS:
		log(128, "qldap_filter: search for %s succeeded\n",
		    filter);
		break;
	case LDAP_TIMEOUT:
	case LDAP_TIMELIMIT_EXCEEDED:
	case LDAP_BUSY:
		log(64, "qldap_filter: search for %s failed (%s)\n", 
		    filter, ldap_err2string(rc) );
		return TIMEOUT;
	case LDAP_NO_SUCH_OBJECT:
		log(64, "qldap_filter: search for %s failed (%s)\n", 
		    filter, ldap_err2string(rc) );
		return NOSUCH;
	default:
		log(64, "qldap_filter: search for %s failed (%s)\n", 
		    filter, ldap_err2string(rc) );
		return FAILED;
	}
	
	q->state = SEARCH;
	return OK;
}

int
qldap_count(qldap *q)
{
	CHECK(q, EXTRACT);
	return ldap_count_entries(q->ld, q->res);
}

int
qldap_first(qldap *q)
{
	CHECK(q, EXTRACT);
	/* get first match of a qldap_filter search */

	q->msg = ldap_first_entry(q->ld, q->res);
	if (q->msg == NULL) {
		if (ldap_count_entries(q->ld, q->res) == 0)
			return NOSUCH;
		else
			return FAILED;
	}
	q->state = EXTRACT;
	return OK;
}

int
qldap_next(qldap *q)
{
	CHECK(q, EXTRACT);
	/* get next match of a qldap_filter search */
	if (q->msg == 0) return FAILED;

	q->msg = ldap_next_entry(q->ld, q->msg);
	if (q->msg == NULL)
		return NOSUCH;
	q->state = EXTRACT;
	return OK;
}

/******  ATTRIBUTE EXTRACTION *************************************************/

static stralloc ldap_attr = {0};

int
qldap_get_uid(qldap *q, int *uid)
{
	unsigned long	ul;
	int	r;

	/* get and check the uid */
	r = qldap_get_attr(q, LDAP_QMAILUID, &ldap_attr, SINGLE_VALUE);
	if (r == OK) {
		if (ldap_attr.s[scan_ulong(ldap_attr.s, &ul)] != '\0')
			r = BADVAL;
		else if (UID_MIN <= ul && ul <= UID_MAX)
			*uid = ul;
		else
			r = ILLVAL;
	} else if (r == NOSUCH && default_uid != 0) {
		*uid = default_uid;
		return OK;
	} else if (r == NOSUCH)
		return NEEDED;
	return r;
}

int
qldap_get_gid(qldap *q, int *gid)
{
	unsigned long	ul;
	int	r;

	/* get and check the gid */
	r = qldap_get_attr(q, LDAP_QMAILGID, &ldap_attr, SINGLE_VALUE);
	if (r == OK) {
		if (ldap_attr.s[scan_ulong(ldap_attr.s, &ul)] != '\0')
			r = BADVAL;
		else if (GID_MIN <= ul && ul <= GID_MAX)
			*gid = ul;
		else
			r = ILLVAL;
	} else if (r == NOSUCH && default_gid != 0) {
		*gid = default_gid;
		return OK;
	} else if (r == NOSUCH)
		return NEEDED;
	return r;
}

int
qldap_get_mailstore(qldap *q, stralloc *hd, stralloc *ms)
{
	int	r;
	/* 
	 * get and check the mailstores.
	 * Both homedir and maildir are set from the three
	 * values ~control/ldapmessagestore, homedirectory
	 * and mailmessagestore.
	 * ms is only filled with a value if both homedir
	 * and maildir is used.
	 */
	r = qldap_get_attr(q, LDAP_HOMEDIR, hd, SINGLE_VALUE);
	if (r == NOSUCH) {
		if (!stralloc_copys(hd, "")) return ERRNO;
	} else if (r != OK)
		return r;
	log(128, "qldap_get_mailstore: hd \"%S\" len %i\n", hd, hd->len);
	if (0 < hd->len) {
		if (hd->s[0] != '/' || check_paths(hd->s) == 0) {
			/* probably some log warning would be good */
			return ILLVAL;
		}
	}
	
	r = qldap_get_attr(q, LDAP_MAILSTORE, ms, SINGLE_VALUE);
	if (r == NOSUCH) {
		if (!stralloc_copys(ms, "")) return ERRNO;
	} else if (r != OK)
		return r;
	log(128, "qldap_get_mailstore: ms \"%S\" len %i\n", ms, ms->len);
	if (ms->len > 0)
		if (check_paths(ms->s) == 0) {
			/* probably some log warning would be good */
			return ILLVAL;
		}
	
	if (hd->len > 0 && ms->len > 0) return OK;
	if (hd->len > 0) return OK;
	if (ms->len > 0) {
		if (ms->s[0] != '/') {
			if (default_messagestore.s == 0 ||
			    default_messagestore.len == 0)
				return ILLVAL;
			if (!stralloc_cat(hd, &default_messagestore))
				return ERRNO;
		}
		if (!stralloc_cat(hd, ms))
			return ERRNO;
		if (!stralloc_copys(ms, "")) return ERRNO;
		return OK;
	}
	return NEEDED;
}

int
qldap_get_user(qldap *q, stralloc *user)
{
	int	r;

	/* get the user name */
	r = qldap_get_attr(q, LDAP_UID, user, SINGLE_VALUE);
	if (r != OK) return r;
	if (check_users(user->s) == 0) {
		/* probably some log warning would be good */
		return ILLVAL;
	}
	return r;
}

int
qldap_get_status(qldap *q, int *status)
{
	int	r;
	
	/* default value */
	*status = STATUS_UNDEF;
	/* get and check the status of the account */
	r = qldap_get_attr(q, LDAP_ISACTIVE, &ldap_attr, SINGLE_VALUE);
	if (r == NOSUCH) {
		return OK;
	} else if (r == OK) {
		if (!case_diffs(ldap_attr.s, ISACTIVE_BOUNCE))
			*status = STATUS_BOUNCE;
		else if (!case_diffs(ldap_attr.s, ISACTIVE_DELETE))
			*status = STATUS_BOUNCE;
		else if (!case_diffs(ldap_attr.s, STATUS_NOPOP))
			*status = STATUS_NOPOP;
		else	*status = STATUS_OK; /* default to OK */
		/* perhaps we should spill out a warning for unknown settings */
		return OK;
	}
	return r;
}

int
qldap_get_dotmode(qldap *q, stralloc *dm)
{
	int	r;

	/* get and check the status of the account */
	r = qldap_get_attr(q, LDAP_DOTMODE, &ldap_attr, SINGLE_VALUE);
	if (r == NOSUCH) {
		if (!stralloc_copy(dm, &dotmode)) return ERRNO;
		return OK;
	}
	if (r != OK)
		return r;

	if (!case_diffs(DOTMODE_LDAPONLY, ldap_attr.s)) {
		if (!stralloc_copys(dm, DOTMODE_LDAPONLY)) return ERRNO;
	} else if (!str_diff(DOTMODE_LDAPWITHPROG, ldap_attr.s)) {
		if (!stralloc_copys(dm, DOTMODE_LDAPWITHPROG)) return ERRNO;
	} else if (!str_diff(DOTMODE_DOTONLY, ldap_attr.s)) {
		if (!stralloc_copys(dm, DOTMODE_DOTONLY)) return ERRNO;
	} else if (!str_diff(DOTMODE_BOTH, ldap_attr.s)) {
		if (!stralloc_copys(dm, DOTMODE_BOTH)) return ERRNO;
	} else if (!str_diff(DOTMODE_NONE, ldap_attr.s)) {
		if (!stralloc_copys(dm, DOTMODE_NONE)) return ERRNO;
	} else {
		return ILLVAL;
	}
	if (!stralloc_0(dm)) return ERRNO;
	return OK;
}

int
qldap_get_quota(qldap *q, unsigned long *size, unsigned long *count,
    unsigned long *max)
/* XXX move to a quota file? Currently I don't think so. */
{
	int	r;
	
	*size = quotasize;
	*count = quotacount;
	*max = 0;
	
	/* First get the maximum mail size. */
	r = qldap_get_ulong(q, LDAP_MAXMSIZE, max);
	if (r != OK && r != NOSUCH)
		return r;

	r = qldap_get_ulong(q, LDAP_QUOTA_SIZE, size);
	if (r != OK && r != NOSUCH)
		return r;
	r = qldap_get_ulong(q, LDAP_QUOTA_COUNT, count);
	if (r != OK && r != NOSUCH)
		return r;

	return OK;
}

int
qldap_get_dn(qldap *q, stralloc *dn)
{
	char *d;
	
	CHECK(q, EXTRACT);

	d = ldap_get_dn(q->ld, q->msg);
	if (d == (char *)0)
		return NOSUCH;
	if (!stralloc_copys(dn, d) || !stralloc_0(dn))
		return ERRNO;
	ldap_memfree(d);
	return OK;
}

int
qldap_get_ulong(qldap *q, const char *attr, unsigned long *ul)
{
	unsigned long ulval;
	int	r;

	r = qldap_get_attr(q, attr, &ldap_attr, SINGLE_VALUE);
	if (r == OK) {
		if (ldap_attr.s[scan_ulong(ldap_attr.s, &ulval)] != '\0')
			return BADVAL;
		*ul = ulval;
	}
	return r;
}

int
qldap_get_bool(qldap *q, const char *attr, int *bool)
{
	int	r;

	r = qldap_get_attr(q, attr, &ldap_attr, SINGLE_VALUE);
	if (r == OK) {
		if (!case_diffs("TRUE", ldap_attr.s))
			*bool = 1;
		else if (!case_diffs("1", ldap_attr.s))
			*bool = 1;
		else if (!case_diffs("FALSE", ldap_attr.s))
			*bool = 0;
		else if (!case_diffs("0", ldap_attr.s))
			*bool = 0;
		else
			return BADVAL;
	}
	return r;
}

int
qldap_get_attr(qldap *q, const char *attr, stralloc *val, int multi)
{
	char	**vals;
	int	nvals, i, j, l, r;
	char	sc = ':';
	/*
	 * extract value of attr if multivalue use ':' as
	 * separator and escape the sep value with '\\'. 
	 */
	CHECK(q, EXTRACT);
	
	vals = ldap_get_values(q->ld, q->msg, attr);
	if (vals == (char **)0) {
#if 0
		/*
		 * XXX this does not work. ldap_result2error returns
		 * the result of the bind action in other words success
		 */
		/* error occured maybe LDAP_NO_SUCH_ATTRIBUTE */
		r = ldap_result2error(q->ld, q->msg, 0);
		switch (r) {
		case LDAP_NO_SUCH_ATTRIBUTE:
			log(128, "qldap_get_attr: %s\n",
			    ldap_err2string(r));
			return NOSUCH;
		default:
			log(128, "qldap_get_attr: %s\n",
			    ldap_err2string(r));
			return FAILED;
		}
#endif
		log(128, "qldap_get_attr(%s): no such attribute\n", attr);
		return NOSUCH;
	}
	nvals = ldap_count_values(vals);
	
	r = FAILED;
	switch (multi) {
	case SINGLE_VALUE:
		if (nvals > 1) {
			r = TOOMANY;
			break;
		}
		if (!stralloc_copys(val, vals[0])) goto fail;
		if (!stralloc_0(val)) goto fail;
		r = OK;
		break;
	case MULTI_VALUE:
		if (!stralloc_copys(val, "")) goto fail;
		for (i = 0; i < nvals; i++) {
			if (i != 0)
				if (!stralloc_append(val, &sc))
					goto fail;
			l = str_len(vals[i]);
			for (j = 0; j < l; j++) {
				if (vals[i][j] == sc)
					if (!stralloc_append(val, "\\"))
						goto fail;
				if (!stralloc_append(val, &vals[i][j]))
					goto fail;
			}
		}
		if (!stralloc_0(val)) goto fail;
		r = OK;
		break;
	case OLDCS_VALUE:
		if (!stralloc_copys(val, "")) goto fail;
		for (i = 0; i < nvals; i++) {
			if (i != 0) if (!stralloc_append(val, &sc)) goto fail;
			byte_repl(vals[i], str_len(vals[i]), ',', sc);
			if (!stralloc_cats(val, vals[i])) goto fail;
		}
		if (!stralloc_0(val)) goto fail;
		r = OK;
		break;
	}
	ldap_value_free(vals);

	log(128, "qldap_get_attr(%s): %s\n", attr, val->s);
	return r;

fail:
	r = errno;
	ldap_value_free(vals);
	stralloc_copys(val, "");
	errno = r;
	return ERRNO;
}

/******  HELPER FUNCTIONS  ****************************************************/

/*
 * For LDAP, '(', ')', '\', '*' and '\0' have to be escaped with '\'.
 * We ignore the '\0' case because it is not possible to have a '\0' in s.
 */
char *
ldap_escape(char *s)
{
	static stralloc escaped = {0};
	char	x;

	/* pre reserve some space */
	if (!stralloc_ready(&escaped, str_len(s))) return 0;
	if (!stralloc_copys(&escaped, "")) return 0;
	do {
		x = *s;
		if (x == '*' || x == '(' || x == ')' || x == '\\')
			if (!stralloc_append(&escaped, "\\")) return 0;
		if (!stralloc_append(&escaped, s)) return 0;
	} while (*s++);
	return escaped.s;
}

char *
ldap_ocfilter(char *searchfilter)
{
	static stralloc filter = {0};

	if (searchfilter == (char *)0) return 0;
	if (objectclass.s == (char *)0 || objectclass.len == 0)
		return searchfilter;
	/* (&(objectclass=...)%searchfilter%) */
	if (!stralloc_copys(&filter, "(&(") ||
	    !stralloc_cats(&filter, LDAP_OBJECTCLASS) ||
	    !stralloc_cats(&filter, "=") ||
	    !stralloc_cat(&filter, &objectclass) ||
	    !stralloc_cats(&filter, ")") ||
	    !stralloc_cats(&filter, searchfilter) ||
	    !stralloc_cats(&filter, ")") ||
	    !stralloc_0(&filter))
		return 0;
	return filter.s;
}

/******  INTERNAL LDAP FUNCTIONS  *********************************************/

/*
 * The rebind procedure - this gets called when the application must
 * perform a bind operation to follow a referral. Works only with OpenLDAP.
 */
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static int dorebind(LDAP *, LDAP_CONST char *, ber_tag_t , ber_int_t, void *);


static int
dorebind(LDAP *ld, LDAP_CONST char *url,
    ber_tag_t request, ber_int_t msgid, void *dummy)
{
	int		r;
	LDAPURLDesc	*srv;

	/* the url parse is just for debugging */
	if( (r = ldap_url_parse(url, &srv)) != LDAP_SUCCESS) {
		log(64, "dorebind: parse url failed: %s\n",
		    ldap_err2string(r));
		return r;
	}
	/* Not request is defined in ldap.h - one of LDAP_REQ_XXXXX */
	log(64, "dorebind: referral - host %s:%d, dn \"%s\", "
	    "request %d, msgid %d\n",
	    srv->lud_host, srv->lud_port, srv->lud_dn, request, msgid);
	ldap_free_urldesc(srv);

	r = ldap_simple_bind_s(ld, ldap_login.s, ldap_password.s);
	if (r != LDAP_SUCCESS) {
		log(64, "dorebind: ldap_simple_bind_s: %s\n",
		    ldap_err2string(r));
	}
	return r;
}
#endif

static int
qldap_set_option(qldap *q, int forceV2)
{
#ifdef LDAP_OPT_PROTOCOL_VERSION
	/*
	 * OpenLDAP 1.x does not have ldap_set_option() so compile only if
	 * available.
	 */
	int	rc, version;
	
	CHECK(q, OPEN);

	if (forceV2 == 1) {
		version = LDAP_VERSION2;
		rc = ldap_set_option(q->ld,
		    LDAP_OPT_PROTOCOL_VERSION, &version);
		if (rc == LDAP_OPT_SUCCESS) {
			log(128, "qldap_set_option LDAPv2 successful\n");
			return OK;
		} else {
			log(128, "qldap_set_option LDAPv2 failed (%s)\n",
			    ldap_err2string(rc));
			return FAILED;
		}
	} else {
		version = LDAP_VERSION3;
		rc = ldap_set_option(q->ld,
		    LDAP_OPT_PROTOCOL_VERSION, &version);
		if (rc != LDAP_OPT_SUCCESS) {
			log(128, "qldap_set_option failed (%s)\n",
			    ldap_err2string(rc));
			return qldap_set_option(q, 1);
		}

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
		/*
		 * currently we support referrals only with OpenLDAP >= 2.x
		 * 1.x does not support it and the other SDKs have other
		 * rebind functions.
		 */
#if LDAP_VENDOR_VERSION > 20100
		rc = ldap_set_rebind_proc(q->ld, dorebind, (void *)0);
#else
		rc = ldap_set_rebind_proc(q->ld, dorebind);
#endif
		if (rc == LDAP_OPT_SUCCESS) {
			rc = ldap_set_option(q->ld, LDAP_OPT_REFERRALS,
			    LDAP_OPT_ON);
		}
		if (rc != LDAP_OPT_SUCCESS)
			log(128, "qldap_set_option: "
			    "enabling referrals failed (%s)\n",
			    ldap_err2string(rc));
		else 
			log(128, "qldap_set_option: "
			    "set referrals successful\n");
		/* referral errors are ignored */
#endif
	}
#endif
	return OK;
}

static int
check_next_state(qldap *q, int next)
{
	switch (next) {
	case NEW:
		/* NEW is a invalid next state */
		return 0;
	case OPEN:
		/* current state is either NEW or CLOSE */
		if (STATEIN(q, NEW) || STATEIN(q, CLOSE))
			return 1;
		else
			return 0;
	case BIND:
		/* current state is OPEN */
		if (STATEIN(q, OPEN))
			return 1;
		else
			return 0;
	case SEARCH:
		/* current state is one of BIND, SEARCH and EXTRACT */
		if (STATEIN(q, BIND) || STATEIN(q, SEARCH) ||
		    STATEIN(q, EXTRACT))
			return 1;
		else
			return 0;
	case EXTRACT:
		/* current state is EXTRACT */
		if (STATEIN(q, EXTRACT) || STATEIN(q, SEARCH))
			return 1;
		else
			return 0;
	case REBIND:
		/* current state is either EXTRACT or OPEN */
		if (STATEIN(q, EXTRACT) || STATEIN(q, OPEN))
			return 1;
		else
			return 0;
	case CLOSE:
		/* all states allowed */ 
		return 1;
	case ERROR:
		/* ERROR is a invalid next state */
		return 0;
	default:
		/* bad state */
		return 0;
	}
}
