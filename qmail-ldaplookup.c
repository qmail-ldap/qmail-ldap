#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

#include "alloc.h"
#include "auto_usera.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "error.h"
#include "localdelivery.h"
#include "output.h"
#include "qldap.h"
#include "qldap-cluster.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "scan.h"
#include "sgetopt.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "subfd.h"
#include "substdio.h"

#define FATAL "qmail-ldaplookup: fatal: "
#define WARN "qmail-ldaplookup: warning: "

void
temp_nomem(void)
{
        strerr_die2x(111, FATAL, "Out of memory.");
}

void
usage(void) 
{
	output(subfderr,
	    "usage:\t%s [ -d level ] -u uid [ -p passwd ]\n"
	    "\t%s [ -d level ] -m mail\n"
	    "\t%s [ -d level ] -f ldapfilter\n",
	    optprogname, optprogname, optprogname, optprogname);
	output(subfderr,
	    "\t-d level:\tsets log-level to level\n"
	    "\t-u uid: \tsearch for user id uid (pop3/imap lookup)\n"
	    "\t-p passwd:\tpassword for user id lookups (only by root)\n"
	    "\t-m mail:\tlookup the mailaddress\n");
	_exit(1);
}

void fail(qldap *, const char *, int);
void unescape(char *, stralloc *);
static char *uidfilter(char *);


ctrlfunc ctrls[] = {
  qldap_controls,
  localdelivery_init,
#ifdef QLDAP_CLUSTER
  cluster_init,
#endif
#ifdef AUTOHOMEDIRMAKE
  dirmaker_init,
#endif
  0
};

stralloc foo = {0};
stralloc bar = {0};

int main(int argc, char **argv)
{
	enum { unset, uid, mail, filter } mode = unset;
	qldap	*q;
	struct passwd *pw;
	char	*passwd = 0, *value = 0;
	char	*f, *s;
	int	opt, r, done, j, slen, status, id;
	unsigned long size, count, maxsize;
	
	const char *attrs[] = { LDAP_MAIL,
				LDAP_MAILALTERNATE,
				LDAP_UID,
				LDAP_QMAILUID,
				LDAP_QMAILGID,
				LDAP_ISACTIVE,
				LDAP_MAILHOST,
				LDAP_MAILSTORE,
				LDAP_HOMEDIR,
				LDAP_QUOTA_SIZE,
				LDAP_QUOTA_COUNT,
				LDAP_FORWARDS,
				LDAP_PROGRAM,
				LDAP_MODE,
				LDAP_REPLYTEXT,
				LDAP_DOTMODE,
				LDAP_MAXMSIZE,
				LDAP_OBJECTCLASS,
#if 0
				LDAP_GROUPCONFIRM,
				LDAP_GROUPMEMONLY,
				LDAP_GROUPCONFRIMTEXT,
				LDAP_GROUPMODERATTEXT,
				LDAP_GROUPMODERATDN,
				LDAP_GROUPMODERAT822,
				LDAP_GROUPMEMBERDN,
				LDAP_GROUPMEMBER822,
				LDAP_GROUPMEMBERFILTER,
#endif
				LDAP_PASSWD,
				0};

	while ((opt = getopt(argc, argv, "d:u:m:p:f:")) != opteof)
		switch (opt) {
		case 'd':
			if (env_put2("LOGLEVEL", optarg) == 0)
				strerr_die2sys(1, FATAL, "setting loglevel: ");
			break;
		case 'u':
			if (value != 0)
				usage();
			value = optarg;
			mode = uid;
			break;
		case 'm':
			if (value != 0)
				usage();
			value = optarg;
			mode = mail;
			break;
		case 'f':
			if (value != 0)
				usage();
			value = optarg;
			mode = filter;
			break;
		case 'p':
			if (geteuid() != 0)
				strerr_die2x(1, FATAL,
				    "only the superuser may comapre passwords");
			passwd = optarg;
			break;
		default:
			usage();
		}
	if (argc != optind) usage();

	log_init(STDERR, -1, 0);

	if (read_controls(ctrls) != 0)
		strerr_die2sys(111, FATAL, "unable to read controls: ");
	
	strerr_warn2(WARN, "program not yet fully finished", 0);
	q = qldap_new();
	if (q == 0)
		return ERRNO;
	
	r = qldap_open(q);
	if (r != OK) fail(q, "qldap_open", r);
	r = qldap_bind(q, 0, 0);
	if (r != OK) fail(q, "qldap_open", r);

	if (qldap_need_rebind() != 0)
		attrs[sizeof(attrs)/4 - 2] = 0; /* password */
	done = 0;
	do {
		switch (mode) {
		case mail:
			f = filter_mail(value, &done);
			if (value == 0)
				strerr_die2sys(1, FATAL, "building filter: ");
			break;
		case uid:
			f = filter_uid(value);
			done = 1;
			if (value == 0)
				strerr_die2sys(1, FATAL, "building filter: ");
			break;
		case filter:
			f = value;
			break;
		default:
			usage();
		}
		output(subfdout, "Searching ldap for:\n%s\nunder dn: %s\n\n",
		    f, qldap_basedn());
		r = qldap_filter(q, f, attrs, qldap_basedn(),
		    SCOPE_SUBTREE);
		if (r != OK) fail(q, "qldap_filter", r);

		r = qldap_count(q);
		if (r == -1) fail(q, "qldap_count", FAILED);
		output(subfdout, "Found %i entries\n\n", r);
	} while (r == 0 && !done);

	r = qldap_first(q);
	if (r != OK) fail(q, "qldap_first", r);;
	do {
		r = qldap_get_dn(q, &foo);
		if (r != OK) fail(q, "qldap_get_dn", r);
		output(subfdout, "dn: %s\n"
		    "-------------------------------------------------------\n",
		    foo.s);
		
		r = qldap_get_attr(q, LDAP_OBJECTCLASS, &foo, MULTI_VALUE);
		if (r != OK) fail(q, "qldap_get_attr(" LDAP_OBJECTCLASS ")", r);
		unescape(foo.s, &bar);
		s = bar.s;
		slen = bar.len-1;
		for(;;) {
			output(subfdout, "%s: %s\n",LDAP_OBJECTCLASS ,s);
			j = byte_chr(s,slen,0);
			if (j++ == slen) break;
			s += j; slen -= j;
		}
		
		r = qldap_get_attr(q, LDAP_MAIL, &foo, SINGLE_VALUE);
		if (r != OK) fail(q, "qldap_get_attr(" LDAP_MAIL ")", r);
		output(subfdout, "%s: %s\n", LDAP_MAIL, foo.s);

		r = qldap_get_attr(q, LDAP_MAILALTERNATE, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_MAILALTERNATE ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n",
				    LDAP_MAILALTERNATE, s);
				j = byte_chr(s,slen,0);
				if (j++ == slen) break;
				s += j; slen -= j;
			}
		}
		
		r = qldap_get_user(q, &foo);
		if (r != OK && r != NOSUCH) fail(q, "qldap_get_user", r);
		if (r == OK)
			output(subfdout, "%s: %s\n", LDAP_UID, foo.s);
		else
			output(subfdout, "%s: undefined "
			    "(forward only account required)\n", LDAP_UID);

		r = qldap_get_status(q, &status);
		if (r != OK) fail(q, "qldap_get_status", r);
		switch (status) {
		case STATUS_BOUNCE:
			output(subfdout, "%s: %s\n",
			    LDAP_ISACTIVE, ISACTIVE_BOUNCE);
			break;
		case STATUS_NOPOP:
			output(subfdout, "%s: %s\n",
			    LDAP_ISACTIVE, ISACTIVE_NOPOP);
			break;
		case STATUS_OK:
			output(subfdout, "%s: %s\n",
			    LDAP_ISACTIVE, ISACTIVE_ACTIVE);
			break;
		case STATUS_UNDEF:
			output(subfdout, "%s: %s\n", LDAP_ISACTIVE,
			    "undefined -> active");
			break;
		default:
			strerr_warn2(WARN,
			    "qldap_get_status returned unknown status", 0);
		}
		
		r = qldap_get_attr(q, LDAP_MAILHOST, &foo, SINGLE_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_MAILHOST ")", r);
		if (r == OK) {
			output(subfdout, "%s: %s\n", LDAP_MAILHOST, foo.s);
			/*
			 * TODO we could check if we are in cluster mode and 
			 * if we would redirect to a differnet host
			 */
		} else
			output(subfdout, "%s: undefined\n", LDAP_MAILHOST);

		/* get the path of the maildir or mbox */
		r = qldap_get_mailstore(q, &foo, &bar);
		switch (r) {
		case OK:
			output(subfdout, "homeDirectory: %s\n", foo.s);
			if (bar.len > 0)
				output(subfdout, "aliasEmpty: %s\n", bar.s);
			else
				output(subfdout, "aliasEmpty: using default\n");
			break;
		case NEEDED:
			output(subfdout,
			    "forward only delivery via alias user\n");
			pw = getpwnam(auto_usera);
			if (!pw)
				strerr_die4x(100, FATAL,
				    "Aiiieeeee, now alias user '",
				    auto_usera, "'found in /etc/passwd.");
			output(subfdout, "alias user: %s\n", pw->pw_name);
			output(subfdout, "alias user uid: %i\n", pw->pw_uid);
			output(subfdout, "alias user gid: %i\n", pw->pw_gid);
			output(subfdout, "alias user home: %s\n", pw->pw_dir);
			output(subfdout, "alias user aliasempty: %s\n",
			    ALIASDEVNULL);
			/* get the forwarding addresses */
			r = qldap_get_attr(q, LDAP_FORWARDS, &foo, MULTI_VALUE);
			if (r != OK)
				fail(q, "qldap_get_attr("
				    LDAP_FORWARDS ") for forward only user", r);
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n", LDAP_FORWARDS, s);
				j = byte_chr(s,slen,0);
				if (j++ == slen) break;
				s += j; slen -= j;
			}
			qldap_free(q);
			return 0;
		default:
			fail(q, "qldap_get_mailstore", r);
		}
		
		r = qldap_get_dotmode(q, &foo);
		if (r != OK) fail(q, "qldap_get_dotmode", r);
		output(subfdout, "%s: %s\n", LDAP_DOTMODE, foo.s);

		r = qldap_get_uid(q, &id);
		if (r != OK) fail(q, "qldap_get_uid", r);
		output(subfdout, "%s: %i\n", LDAP_QMAILUID, id);
		
		r = qldap_get_gid(q, &id);
		if (r != OK) fail(q, "qldap_get_gid", r);
		output(subfdout, "%s: %i\n", LDAP_QMAILGID, id);
		
		r = qldap_get_quota(q, &size, &count, &maxsize);
		if (r != OK) fail(q, "qldap_get_quota", r);
		output(subfdout, "%s: %u%s\n", LDAP_QUOTA_SIZE, size,
		    size==0?" (unlimited)":"");
		output(subfdout, "%s: %u%s\n", LDAP_QUOTA_COUNT, count,
		    count==0?" (unlimited)":"");
		output(subfdout, "%s: %u%s\n", LDAP_MAXMSIZE, maxsize,
		    maxsize==0?" (unlimited)":"");

		r = qldap_get_attr(q, LDAP_MODE, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_MODE ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				if (case_diffs(MODE_FORWARD, s) &&
				    case_diffs(MODE_REPLY, s) &&
				    case_diffs(MODE_NOLOCAL, s) &&
				    case_diffs(MODE_NOMBOX, s) &&
				    case_diffs(MODE_NOFORWARD, s) &&
				    case_diffs(MODE_NOPROG, s) &&
				    case_diffs(MODE_LOCAL, s) &&
				    case_diffs(MODE_FORWARD, s) &&
				    case_diffs(MODE_PROG, s) &&
				    case_diffs(MODE_NOREPLY, s))
					strerr_warn4(WARN,
					    "undefined mail delivery mode: ",
					    s," (ignored).", 0);
				else if (!case_diffs(MODE_FORWARD, s))
					strerr_warn4(WARN,
					    "mail delivery mode: ",
					    s," should not be used "
					    "(used internally).", 0);
				output(subfdout, "%s: %s\n", LDAP_MODE, s);
				j = byte_chr(s,slen,0);
				if (j++ == slen) break;
				s += j; slen -= j;
			}
		}

		r = qldap_get_attr(q, LDAP_FORWARDS, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_FORWARDS ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n", LDAP_FORWARDS, s);
				j = byte_chr(s,slen,0);
				if (j++ == slen) break;
				s += j; slen -= j;
			}
		}

		r = qldap_get_attr(q, LDAP_PROGRAM, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_PROGRAM ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n", LDAP_PROGRAM, s);
				j = byte_chr(s,slen,0);
				if (j++ == slen) break;
				s += j; slen -= j;
			}
		}

		r = qldap_get_attr(q, LDAP_REPLYTEXT, &foo, SINGLE_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_REPLYTEXT ")", r);
		if (r == OK)
			output(subfdout, "%s:\n=== begin ===\n%s\n"
			    "=== end ===\n", LDAP_REPLYTEXT, foo.s);
		else
			output(subfdout, "%s: undefined\n", LDAP_REPLYTEXT);

		r = qldap_next(q);
		output(subfdout, "\n\n");
	} while (r == OK);
	if (r != NOSUCH) fail(q, "qldap_next", r);
	qldap_free(q);
	return 0;
}

void
fail(qldap *q, const char *f, int r)
{
	qldap_free(q);
	strerr_die4x(111, FATAL, f ,": ", qldap_err_str(r));
}

void
unescape(char *s, stralloc *t)
{
  if (!stralloc_copys(t, "")) temp_nomem();
  do {
    if (s[0] == '\\' && s[1] == ':') s++;
    else if (s[0] == ':') {
      if (!stralloc_0(t)) temp_nomem();
      continue;
    }
    if (!stralloc_append(t, s)) temp_nomem();
  } while (*s++);
}

