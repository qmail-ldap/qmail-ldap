#include <unistd.h>

#include "alloc.h"
#include "auto_break.h"
#include "byte.h"
#include "case.h"
#include "coe.h"
#include "control.h"
#include "env.h"
#include "error.h"
#include "fd.h"
#include "fmt.h"
#include "getln.h"
#include "ndelay.h"
#include "now.h"
#include "open.h"
#include "qldap.h"
#include "qldap-errno.h"
#include "qmail.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "readwrite.h"
#include "seek.h"
#include "sig.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"
#include "wait.h"

#define FATAL "qmail-group: fatal: "

void
temp_nomem(void)
{
	strerr_die2x(111, FATAL, "Out of memory.");
}
void
temp_qmail(char *fn)
{
	strerr_die4sys(111, FATAL, "Unable to open ", fn, ": ");
}
void
temp_rewind(void)
{
	strerr_die2x(111, FATAL, "Unable to rewind message.");
}
void
temp_read(void)
{
	strerr_die2x(111, FATAL, "Unable to read message.");
}
void
temp_fork(void)
{
	strerr_die2sys(111, FATAL, "Unable to fork: ");
}
void usage(void)
{
	strerr_die1x(100, "qmail-group: usage: qmail-group Maildir");
}

void init(void);
void bouncefx(void);
void blast(void);
void reopen(void);
void trydelete(void);
void secretary(char *, int);
void explode(qldap *);
void subscribed(qldap *, int);
qldap *ldapgroup(char *, int *, int *, int *, int *);

char *sender;
char *dname;

int
main(int argc, char **argv)
{
	qldap *qlc;
	char *maildir;
	int flagm, flagc, flags, flagS;
	
	if (argv[1] == 0) usage();
	if (argv[2] != 0) usage();
	maildir = argv[1];
	
	init();
	/* filter out loops as soon as poosible */
	bouncefx();
	
	flagc = flags = flagS = flagm = 0;
	qlc = ldapgroup(dname, &flagc, &flags, &flagS, &flagS);
	/* need to distinguish between new messages and responses */

	if (flagc)
		secretary(maildir, 0);
	if (flags)
		subscribed(qlc, flagS);
	if (flagm) {
		secretary(maildir, 1);
	}

	explode(qlc);
	qldap_free(qlc);
	
	/* does not return */
	blast();
	return 111;
}

stralloc grouplogin = {0};
stralloc grouppassword = {0};

int
init_controls(void)
{
	switch (control_readline(&grouplogin, "control/ldapgrouplogin")) {
	case 0:
		return 0;
	case 1:
		break;
	default:
		return -1;
	}
	if (!stralloc_0(&grouplogin)) return -1;

	if (control_rldef(&grouppassword, "control/ldapgrouppassword",
		    0, "") == -1)
		return -1;
	if (!stralloc_0(&grouppassword)) return -1;

	return 0;
}

ctrlfunc ctrls[] = {
	qldap_ctrl_trylogin,
	qldap_ctrl_generic,
	init_controls,
	0
};

stralloc base = {0};
stralloc dtline = {0};
char *local;
char *host;

void
init(void)
{
	char *t;
	unsigned int i;

	/* read some control files */
	if (read_controls(ctrls) == -1)
		strerr_die2x(100, FATAL, "unable to read controls");

	sender = env_get("SENDER");
	if (!sender) strerr_die2x(100, FATAL, "SENDER not set");
	local = env_get("LOCAL");
	if (!local) strerr_die2x(100, FATAL, "LOCAL not set");
	host = env_get("HOST");
	if (!host) strerr_die2x(100, FATAL, "HOST not set");
	dname = env_get(ENV_GROUP);
	if (!dname) strerr_die2x(100, FATAL, "QLDAPGROUP not set");

	
	t = env_get("EXT");
	if (t != 0) {
		if (!stralloc_copyb(&base, local,
			    str_len(local) - str_len(t) - 1))
			temp_nomem();
	} else {
		if (!stralloc_copys(&base, local)) temp_nomem();
	}
	if (!stralloc_copys(&dtline, "Delivered-To: ")) temp_nomem();
	if (!stralloc_cat(&dtline, &base)) temp_nomem();
	if (!stralloc_cats(&dtline, "@")) temp_nomem();
	if (!stralloc_cats(&dtline, host)) temp_nomem();
	for (i = 0; i < dtline.len; ++i)
		if (dtline.s[i] == '\n')
			dtline.s[i] = '_';
	if (!stralloc_cats(&dtline,"\n")) temp_nomem();
}

char buf[4096];
stralloc line = {0};

void
bouncefx(void)
{
	substdio	ss;
	int		match;
	
	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	for (;;)
	{
		if (getln(&ss, &line, &match, '\n') != 0) temp_read();
		if (!match) break;
		if (line.len <= 1) break;
		if (line.len == dtline.len)
			if (byte_equal(line.s, line.len, dtline.s))
				strerr_die2x(100, FATAL,
				    "this message is looping: "
				    "it already has my Delivered-To line. "
				    "(#5.4.6)");
	}
}

stralloc recips = {0};
char strnum1[FMT_ULONG];
char strnum2[FMT_ULONG];

void
blast(void)
{
	struct qmail qqt;
	substdio ss;
	char *s, *smax;
	const char *qqx;
	unsigned long qp;
	datetime_sec when;
	int match;

	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	
	if (qmail_open(&qqt) == -1) temp_fork();
	qp = qmail_qp(&qqt);
	/* mail header */
	qmail_put(&qqt, dtline.s, dtline.len);
	qmail_puts(&qqt,"Precedence: bulk\n");
	do {
		if (getln(&ss, &line, &match, '\n') != 0) {
			qmail_fail(&qqt);
			break;
		}
		qmail_put(&qqt, line.s, line.len);
	} while (match);

	if (!stralloc_copy(&line,&base)) temp_nomem();
	if (!stralloc_cats(&line,"-return-@")) temp_nomem();
	if (!stralloc_cats(&line,host)) temp_nomem();
	if (!stralloc_cats(&line,"-@[]")) temp_nomem();
	if (!stralloc_0(&line)) temp_nomem();
	qmail_from(&qqt, line.s);
	for (s = recips.s, smax = recips.s + recips.len; s < smax;
	    s += str_len(s) + 1)
		qmail_to(&qqt,s);
	qqx = qmail_close(&qqt);
	if (*qqx)
		strerr_die3x(*qqx == 'D' ? 100 : 111,
		    "Unable to blast message: ", qqx + 1, ".");
	when = now();
	strnum1[fmt_ulong(strnum1, (unsigned long) when)] = 0;
	strnum2[fmt_ulong(strnum2, qp)] = 0;
	trydelete();
	strerr_die5x(0, "qmail-group: ok ", strnum1, " qp ", strnum2, ".");
}

stralloc fname = {0};
char sbuf[1024];

void
reopen(void)
{
	int fd;

	if (!stralloc_0(&fname)) temp_nomem();
	fd = open_read(fname.s);
	if (fd == -1)
		strerr_die2sys(111, FATAL, "Unable to reopen old message: ");
	if (fd_move(0,fd) == -1) 
		strerr_die2sys(111, FATAL,
		    "Unable to reopen old message: fd_move: ");
}

void
trydelete(void)
{
	if (fname.s && fname.len > 1)
		unlink(fname.s);
}

unsigned int nummoderators;
stralloc moderators = {0};

void
secretary(char *maildir, int flagmoderate)
{
	const char **args;
	char *s, *smax;
	int child, wstat;
	unsigned int i, numargs;
	int pi[2];
	int r;

	if (!stralloc_copys(&fname, "")) temp_nomem();

	if (seek_begin(0) == -1) temp_rewind();

	numargs = 4;
	if (flagmoderate == 1)
		numargs += 2 * nummoderators;
	
	args = (const char **) alloc(numargs * sizeof(char *));
	if (!args) temp_nomem();
	i = 0;
	args[i++] = "qmail-secretary";
	if (flagmoderate == 0)
		args[i++] = "-Zc";
	else {
		args[i++] = "-ZC";
		for (s = moderators.s, smax = moderators.s + moderators.len;
		    s < smax; s += str_len(s) + 1) {
			args[i++] = "-m";
			args[i++] = s;
			if (i + 2 > numargs)
			       strerr_die2x(111, FATAL, "internal error.");	
		}
	}
	args[i++] = maildir;
	args[i++] = 0;
	
	if (pipe(pi) == -1)
		strerr_die2sys(111, FATAL,
		    "Unable to run secretary: pipe: ");
	
	coe(pi[0]);
	switch(child = fork()) {
	case -1:
		temp_fork();
	case 0:
		if (fd_move(1,pi[1]) == -1) 
			strerr_die2sys(111, FATAL,
			    "Unable to run secretary: fd_move: ");
		sig_pipedefault();
		execvp(*args, (char **)args);
		strerr_die3x(111,"Unable to run secretary: ",
		    error_str(errno), ". (#4.3.0)");
	}
	close(pi[1]);
	alloc_free(args);
	
	wait_pid(&wstat,child);
	if (wait_crashed(wstat))
		strerr_die2x(111, FATAL, "Aack, child crashed.");
	switch(wait_exitcode(wstat)) {
	case 100:
	case 64: case 65: case 70:
	case 76: case 77: case 78: case 112:
		_exit(100);
	case 0: case 99:
		/* XXX a for(;;) loop would be great */
		r = read(pi[0], sbuf, sizeof(sbuf));
		if (r == -1) /* read error on a readable pipe, be serious */
			strerr_die2sys(111, FATAL,
			    "Unable to read secretary result: ");
		if (r == 0)
			/* need to wait for confirmation */
			_exit(0);
		for (i = 0; i < r; i++) {
			if (i == 0) {
				if (sbuf[i] != 'K')
					strerr_die2x(111, FATAL,
					    "Strange secretary dialect");
				else
					continue;
			}
			if (!stralloc_append(&fname, &sbuf[i])) temp_nomem();
		}
		close(pi[0]);
		reopen();
		return;
	default: _exit(111);
	}
}

/************ LDAP FUNCTIONS AND HELPER FUNCTIONS *************/

stralloc ldapval = {0};
stralloc tmpval = {0};

static int getmoderators(qldap *);
static int unescape(char *, stralloc *, unsigned int *);
static void extract_addrs822(qldap *, const char *, stralloc *, unsigned int *);
static void extract_addrsdn(qldap *, qldap *, const char *, stralloc *,
    unsigned int *);
static void extract_addrsfilter(qldap *, qldap *, const char *, stralloc *,
    unsigned int *);
static int getentry(qldap *, char *);

static int
getmoderators(qldap *q)
{
	qldap *sq;
	int r;
	
	nummoderators = 0; sq = 0;
	if (!stralloc_copys(&moderators, "")) { r = ERRNO; goto fail; }

	extract_addrs822(q, LDAP_GROUPMODERAT822,
	    &moderators, &nummoderators);
	
	/* open a second connection and do some dn lookups */
	sq = qldap_new();
	if (sq == 0) temp_nomem();

	r = qldap_open(sq);
	if (r != OK) goto fail;
	r = qldap_bind(sq, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;
	
	extract_addrsdn(q, sq, LDAP_GROUPMODERATDN,
	    &moderators, &nummoderators);
	
	qldap_free(sq);
	return nummoderators > 0;
	
fail:
	if (sq) qldap_free(sq);
	qldap_free(q);
	strerr_die3x(111, FATAL, "expand group: moderators: ",
	    qldap_err_str(r));
	/* NOTREACHED */
	return 0;
}

void
explode(qldap *q)
{
	qldap *sq;
	int r;

	sq = 0;
	if (!stralloc_copys(&recips, "")) { r = ERRNO; goto fail; }
	extract_addrs822(q, LDAP_GROUPMEMBER822, &recips, 0);

	/* open a second connection and do some dn lookups */
	sq = qldap_new();
	if (sq == 0) temp_nomem();

	r = qldap_open(sq);
	if (r != OK) goto fail;
	r = qldap_bind(sq, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;

	extract_addrsdn(q, sq, LDAP_GROUPMEMBERDN, &recips, 0);
	extract_addrsfilter(q, sq, LDAP_GROUPMEMBERFILTER, &recips, 0);
	
	qldap_free(sq);
	return;
fail:
	if (sq) qldap_free(sq);
	qldap_free(q);
	strerr_die3x(111, FATAL, "expand group: members: ", qldap_err_str(r));
	/* NOTREACHED */
}

stralloc founddn = {0};

void
subscribed(qldap *q, int flagS)
{
	qldap *sq;
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *s, *smax;
	int r;

	sq = 0;
	if (!stralloc_copys(&recips, "")) { r = ERRNO; goto fail; }
	extract_addrs822(q, flagS ? LDAP_GROUPSENDER822 : LDAP_GROUPMEMBER822,
	    &recips, 0);
	
	for (s = recips.s, smax = recips.s + recips.len; s < smax;
	    s += str_len(s) + 1)
		if (!case_diffs(sender, s)) return;

	/* open a second connection and do some dn lookups */
	sq = qldap_new();
	if (sq == 0) temp_nomem();

	r = qldap_open(sq);
	if (r != OK) goto fail;
	r = qldap_bind(sq, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;

	r = getentry(sq, sender);
	if (r == NOSUCH) {
		qldap_free(sq);
		qldap_free(q);
		strerr_die2x(100, FATAL,
		    "You are not allowed to post to this list. (#5.7.2)");
	}
	if (r != OK) goto fail;
	
	r = qldap_get_dn(sq, &founddn);
	if (r != OK) goto fail;
	
	r = qldap_get_attr(q, flagS ? LDAP_GROUPSENDERDN : LDAP_GROUPMEMBERDN,
	    &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1)
		if (!case_diffs(s, founddn.s)) {
			qldap_free(sq);
			return;
		}

	r = qldap_get_attr(q,
	    flagS ? LDAP_GROUPSENDERFILTER : LDAP_GROUPMEMBERFILTER,
	    &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1) {
		r = qldap_filter(sq, founddn.s, attrs, founddn.s, SCOPE_BASE);
		if (r == NOSUCH) continue;
		if (r != OK) goto fail;
		if (qldap_count(sq) < 1) continue;
		/* match found */
		qldap_free(sq);
		return;
	}
	qldap_free(sq);
	qldap_free(q);
	strerr_die2x(100, FATAL,
	    "You are not allowed to post to this list. (#5.7.2)");
fail:
	if (sq) qldap_free(sq);
	qldap_free(q);
	strerr_die5x(111, FATAL, "sender ", sender, " verification failed: ",
	    qldap_err_str(r));
	/* NOTREACHED */
}


qldap *
ldapgroup(char *dn, int *flagc, int *flags, int *flagS, int *flagm)
{
	qldap *q;
	const char *attrs[] = {
		LDAP_GROUPCONFIRM,
		LDAP_GROUPMEMONLY,
		LDAP_GROUPCONFRIMTEXT,
		LDAP_GROUPMODERATTEXT,
		LDAP_GROUPMODERATDN,
		LDAP_GROUPMODERAT822,
		LDAP_GROUPMEMBERDN,
		LDAP_GROUPMEMBER822,
		LDAP_GROUPMEMBERFILTER,
		LDAP_GROUPSENDERDN,
		LDAP_GROUPSENDER822,
		LDAP_GROUPSENDERFILTER,
		0 };
	int r;
		
	q = qldap_new();
	if (q == 0) temp_nomem();

	r = qldap_open(q);
	if (r != OK) goto fail;
	r = qldap_bind(q, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;

	r = qldap_filter(q, "objectclass=*", attrs, dn, SCOPE_BASE);
	if (r != OK) goto fail;
	r = qldap_count(q);
	if (r != 1) {
		/* TOOMANY should be impossible with SCOPE_BASE */
		r = r==0?NOSUCH:TOOMANY;
		goto fail;
	}
	r = qldap_first(q); /* and only */
	if (r != OK) goto fail;
	
	r = qldap_get_bool(q, LDAP_GROUPCONFIRM, flagc);
	if (r != OK && r != NOSUCH) goto fail;
	
	r = qldap_get_bool(q, LDAP_GROUPMEMONLY, flags);
	if (r != OK && r != NOSUCH) goto fail;
	
	r = qldap_get_attr(q, LDAP_GROUPCONFRIMTEXT, &ldapval, SINGLE_VALUE);
	switch (r) {
	case OK:
		if (!env_put2("CONFIRMMESS", ldapval.s)) {
			r = ERRNO;
			goto fail;
		}
		break;
	case NOSUCH:
		if (!env_unset("CONFIRMMESS")) {
			r = ERRNO;
			goto fail;
		}
		break;
	default:
		goto fail;
	}
	
	r = qldap_get_attr(q, LDAP_GROUPMODERATTEXT, &ldapval, SINGLE_VALUE);
	switch (r) {
	case OK:
		if (!env_put2("APPROVEMESS", ldapval.s)) {
			r = ERRNO;
			goto fail;
		}
		break;
	case NOSUCH:
		if (!env_unset("APPROVEMESS")) {
			r = ERRNO;
			goto fail;
		}
		break;
	default:
		goto fail;
	}

	*flagm = getmoderators(q);
	
	if (flags) {
		r = qldap_get_attr(q, LDAP_GROUPSENDERDN,
		    &ldapval, MULTI_VALUE);
		switch (r) {
		case OK:
			*flagS = 1;
			goto done;
		case NOSUCH:
			break;
		default:
			goto fail;
		}
		r = qldap_get_attr(q, LDAP_GROUPSENDER822,
		    &ldapval, MULTI_VALUE);
		switch (r) {
		case OK:
			*flagS = 1;
			goto done;
		case NOSUCH:
			break;
		default:
			goto fail;
		}
		r = qldap_get_attr(q, LDAP_GROUPSENDERFILTER,
		    &ldapval, MULTI_VALUE);
		switch (r) {
		case OK:
			*flagS = 1;
			goto done;
		case NOSUCH:
			break;
		default:
			goto fail;
		}
done:
	}
	
	return q;

fail:
	qldap_free(q);
	strerr_die3x(111, FATAL, "get ldap group entry: ", qldap_err_str(r));
	/* NOTREACHED */
	return 0;
}

static int
unescape(char *s, stralloc *t, unsigned int *count)
{
	do {
		if (s[0] == '\\' && s[1] == ':') s++;
		else if (s[0] == ':') {
			if (count) *count += 1;
			if (!stralloc_0(t)) return ERRNO;
			continue;
		}
		if (!stralloc_append(t, s)) return ERRNO;
	} while (*s++);
	if (count) *count += 1;
	return OK;
}

static void
extract_addrs822(qldap *q, const char *attr, stralloc *list,
    unsigned int *numlist)
{
	int r;

	r = qldap_get_attr(q, attr, &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, list, numlist);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	return;
fail:
	qldap_free(q);
	strerr_die5x(111, FATAL, "expand group attr: ", attr, ": ",
	    qldap_err_str(r));
	/* NOTREACHED */
}
	
static void
extract_addrsdn(qldap *q, qldap *sq, const char *attr,
    stralloc *list, unsigned int *numlist)
{
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *s, *smax;
	int r;

	if (!stralloc_copys(&tmpval, "")) { r = ERRNO; goto fail; }
	r = qldap_get_attr(q, attr, &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1) {
		r = qldap_filter(sq, "objectclass=*", attrs, s, SCOPE_BASE);
		if (r == NOSUCH) continue;
		if (r != OK) goto fail;
		r = qldap_count(sq);
		if (r > 1) {
			/* TOOMANY should be impossible with SCOPE_BASE */
			r = TOOMANY;
			goto fail;
		} else if (r <= 0)
			continue;
		r = qldap_first(sq); /* and only */
		if (r != OK) goto fail;
		/* get mail address */
		r = qldap_get_attr(sq, LDAP_MAIL, &ldapval, SINGLE_VALUE);
		switch (r) {
		case OK:
			if (!stralloc_cat(list, &ldapval)) {
				r = ERRNO;
				goto fail;
			}
			if (numlist) *numlist += 1;
			break;
		case NOSUCH:
			/* WTF! Ignore. */
			break;
		default:
			goto fail;
		}
		/* free stuff for next search */
		qldap_free_results(sq);
	}
	return;
	
fail:
	qldap_free(sq);
	qldap_free(q);
	strerr_die5x(111, FATAL, "expand group attr: ", attr, ": ",
	    qldap_err_str(r));
	/* NOTREACHED */
}

static void
extract_addrsfilter(qldap *q, qldap *sq, const char *attr,
    stralloc *list, unsigned int *numlist)
{
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *s, *smax;
	int r;

	if (!stralloc_copys(&tmpval, "")) { r = ERRNO; goto fail; }
	r = qldap_get_attr(q, attr, &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1) {
		r = qldap_filter(sq, s, attrs, qldap_basedn(), SCOPE_SUBTREE);
		if (r == NOSUCH) continue;
		if (r != OK) goto fail;
		r = qldap_first(sq);
		if (r != OK && r != NOSUCH) goto fail;
		if (r == NOSUCH) {
			qldap_free_results(sq);
			continue;
		}
		do {
			/* get mail address */
			r = qldap_get_attr(sq, LDAP_MAIL, &ldapval,
			    SINGLE_VALUE);
			switch (r) {
			case OK:
				if (!stralloc_cat(list, &ldapval)) {
					r = ERRNO;
					goto fail;
				}
				if (numlist) *numlist += 1;
				break;
			case NOSUCH:
				/* WTF! Ignore. */
				break;
			default:
				goto fail;
			}
			r = qldap_next(sq);
		} while (r == OK);
		if (r != NOSUCH) goto fail;
		
		/* free stuff for next search */
		qldap_free_results(sq);
	}
	return;
	
fail:
	qldap_free(sq);
	qldap_free(q);
	strerr_die5x(111, FATAL, "expand group attr: ", attr, ": ",
	    qldap_err_str(r));
	/* NOTREACHED */
}

stralloc filter = {0};

static int
getentry(qldap *sq, char *mail)
{
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *f;
	int done, rv;

	done = 0;
	do {
		/* build the search string for the email address */
		f = filter_mail(mail, &done);
		if (f == (char *)0) return ERRNO;

		/* do the search for the email address */
		rv = qldap_lookup(sq, f, attrs);
		switch (rv) {
		case OK:
			return OK;
		case NOSUCH:
			break;
		default:
			return rv;
		}
	} while (!done);
	return NOSUCH;
}
