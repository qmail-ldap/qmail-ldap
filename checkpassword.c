#include <sys/types.h>
#include <unistd.h>
#include "auth_mod.h"
#include "auto_uids.h"
#include "byte.h"
#include "check.h"
#include "env.h"
#include "error.h"
#include "fmt.h"
#include "passwd.h"
#include "pbsexec.h"
#include "prot.h"
#include "qldap.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "scan.h"
#include "str.h"
#include "stralloc.h"

#include "checkpassword.h"

int
check(checkfunc *f, stralloc *login, stralloc *authdata,
    struct credentials *c, int fast)
{
	int	i, r;

	for (i = 0; f[i] != 0; i++)
		switch (r = f[i](login, authdata, c, fast)) {
		case OK:
		case FORWARD:
			return r;
		case NOSUCH:
			/* lets try an other backend */
			break;
		case BADPASS:
			/* NOTE: users defined in two dbs are not allowed */
			return BADPASS;
		default:
			return r;
		}
	
	return NOSUCH;
}

char num[FMT_ULONG];

int
check_ldap(stralloc *login, stralloc *authdata,
    struct credentials *c, int fast)
{
	static	stralloc ld = {0};
	qldap	*q;
	char	*filter;
	int	r, status, pwok, needforward;
	unsigned long count, size, max;
	const	char	*attrs[] = {
				LDAP_UID, /* the first 6 attrs are default */
				LDAP_QMAILUID,
				LDAP_QMAILGID,
				LDAP_ISACTIVE,
				LDAP_MAILHOST,
				LDAP_MAILSTORE,
				LDAP_HOMEDIR,
				LDAP_PASSWD, 0}; /* passwd is extra */

	/* TODO more debug output is needed */
	needforward = 0;
	q = qldap_new();
	if (q == 0)
		return ERRNO;
	
	r = qldap_open(q);
	if (r != OK) goto fail;
	r = qldap_bind(q, 0, 0);
	if (r != OK) goto fail;
	
	if (fast) {
		/* just comapre passwords and account status */
		attrs[0] = LDAP_ISACTIVE;
		if (qldap_need_rebind() == 0) {
			attrs[1] = LDAP_PASSWD;
			attrs[2] = 0;
		} else
			attrs[1] = 0;
	} else {
		if (qldap_need_rebind() != 0)
			attrs[7] = 0;
	}

	filter = filter_uid(login->s);
	if (filter == 0) { r = ERRNO; goto fail; }

	r = qldap_lookup(q, filter, attrs);
	if (r != OK) goto fail;

	r = qldap_get_status(q, &status);
	if (r != OK) goto fail;
	if (status == STATUS_BOUNCE || status == STATUS_NOACCESS) {
		qldap_free(q);
		return ACC_DISABLED;
	}
	
	if (!fast) {
#ifdef QLDAP_CLUSTER
		r = qldap_get_attr(q, LDAP_MAILHOST, &c->forwarder,
		    SINGLE_VALUE);
		if (r != OK && r != NOSUCH) goto fail;
		if (r == OK && cluster(c->forwarder.s) == 1) {
			/* hostname is different, so I reconnect */
			log(8, "check_ldap: forwarding session to %s\n",
			    c->forwarder.s);
			needforward = 1;
		}
#endif

		r = qldap_get_uid(q, &c->uid);
		if (r != OK) goto fail;
		r = qldap_get_gid(q, &c->gid);
		if (r != OK) goto fail;
		r = qldap_get_mailstore(q, &c->home, &c->maildir);
		if (r != OK) goto fail;
		size = count = max = 0;
		r = qldap_get_quota(q, &size, &count, &max);
		if (r != OK) goto fail;
		if (max != 0) {
			num[fmt_ulong(num, max)] = 0;
			if (!env_put2("DATASIZE", num))
				auth_error(ERRNO);
		}
		if (size != 0 || count != 0) {
			if (!stralloc_copys(&ld, "")) auth_error(ERRNO);
			if (size != 0) {
				if (!stralloc_catb(&ld, num,
					    fmt_ulong(num, size)))
					auth_error(ERRNO);
				if (!stralloc_append(&ld, "S"))
					auth_error(ERRNO);
			}
			if (count != 0) {
				if (size != 0)
					if (!stralloc_append(&ld, ","))
						auth_error(ERRNO);
				if (!stralloc_catb(&ld, num,
					    fmt_ulong(num, count)))
					auth_error(ERRNO);
				if (!stralloc_append(&ld, "C"))
					auth_error(ERRNO);
			}
			if (!stralloc_0(&ld)) auth_error(ERRNO);
			if (!env_put2(ENV_QUOTA, ld.s )) auth_error(ERRNO);
		}
	}
	
	if (qldap_need_rebind() == 0) {
		r = qldap_get_attr(q, LDAP_PASSWD, &ld, SINGLE_VALUE);
		if (r != OK) goto fail;
		pwok = cmp_passwd(authdata->s, ld.s);
	} else {
		r = qldap_get_dn(q, &ld);
		if (r != OK) goto fail;
		r = qldap_rebind(q, ld.s, authdata->s);
		switch (r) {
		case OK:
			pwok = OK;
			break;
		case LDAP_BIND_AUTH:
			pwok = BADPASS;
			break;
		default:
			pwok = r;
			break;
		}
	}
done:
	log(32, "check_ldap: password compare was %s\n", 
	    pwok == OK?"successful":"not successful");
	qldap_free(q);
	if (pwok == OK  && needforward == 1)
		return FORWARD;
	return pwok;
fail:
	qldap_free(q);
	return r;
	
}

void
change_uid(int uid, int gid)
{
	int	id;
	
	id = geteuid();
	if (id != 0 && (id == uid || id == -1)) {
		/* not running as root so return */
		log(32, "change_uid: already running non root\n");
		return;
	}
	if (uid == -1 && gid == -1) {
		/* run as non-privileged user qmaild group nofiles */
		uid = auto_uidd;
		gid = auto_gidn;
	}
	/* first set the group id */
	if (prot_gid(gid) == -1)
		auth_error(ERRNO);
	log(32, "setgid succeeded (%i)\n", gid);
	
	/* ... then the user id */
	if (prot_uid(uid) == -1)
		auth_error(ERRNO);
	log(32, "setuid succeeded (%i)\n", uid);
	
	/* ... now check that we are realy not running as root */
	if (!getuid())
		auth_error(FAILED);
}

void
setup_env(char *user, struct credentials *c)
{
	/* set up the environment for the execution of the subprogram */
	if (!env_put2("USER", user))
		auth_error(ERRNO);
	
	/* only courier-imap needs this but we set it anyway */
	if (!env_put2("AUTHENTICATED", user))
		auth_error(ERRNO);
	
	if (c->home.s != 0 && c->home.len > 0)
		if (!env_put2("HOME", c->home.s))
			auth_error(ERRNO);
	
	if (c->maildir.s != 0 && c->maildir.len > 0) {
		if (!env_put2("MAILDIR", c->maildir.s))
			auth_error(ERRNO);
	} else {
		if (!env_unset("MAILDIR"))
			auth_error(ERRNO);
	}
	log(32, "environment successfully set: "
	    "USER %s, HOME %s, MAILDIR %s\n",
	    user, c->home.s != 0 && c->home.len > 0?
	    c->home.s:"unset, forwarding",
	    c->maildir.s != 0 && c->maildir.len > 0?
	    c->maildir.s:"unset, using aliasempty"); 
}

