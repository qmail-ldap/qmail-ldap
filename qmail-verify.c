#include "error.h"
#include "getln.h"
#include "qldap.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "stralloc.h"
#include "subfd.h"
#include "substdio.h"
#include "timeoutread.h"

struct qldap *q;

void cleanup(void);
void
die_read(void)
{
	cleanup();
	_exit(1);
}
void
die_write(void)
{
	cleanup();
	_exit(1);
}
void
die_nomem(void)
{
	cleanup();
	_exit(111);
}
void
die_timeout(void)
{
	cleanup();
	_exit(111);
}
void
die_temp(void)
{
	cleanup();
	_exit(111);
}
void
die_control(void)
{
	_exit(100);
}
void
temp_fail(void)
{
	if (substdio_putflush(subfdout, "Z", 2) == -1)
		die_write();
	qldap_free_results(q);
}

void lookup(stralloc *mail);


int timeout = 3;
int
saferead(int fd, void *buf, int len)
{
	return timeoutread(timeout,fd,buf,len);
}

char ssinbuf[512];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

stralloc line = {0};
ctrlfunc	ctrls[] = {
		qldap_controls,
		0 };

int
main(int argc, char **argv)
{
	int match;

	if (read_controls(ctrls) == -1)
		die_control();
	
	q = 0;
	do {
		if (getln(&ssin, &line, &match, '\0') != 0) {
			if (errno != error_timeout)
				die_read();
			cleanup();
			continue;
		}
		if (!match) {
			cleanup(); /* other side closed pipe */
			break;
		}
		lookup(&line);
	} while (1);
	return 0;
}

void
lookup(stralloc *mail)
{
	const char *attrs[] = {  LDAP_ISACTIVE, 0 };
	char *f;
	int done;
	int status;
	int rv;

	/* TODO more debug output is needed */
	if (q == 0) {
		q = qldap_new();
		if (q == 0)
			die_nomem();

		rv = qldap_open(q);
		if (rv != OK) die_temp();
		rv = qldap_bind(q, 0, 0);
		if (rv != OK) die_temp();
	}
	
	/*
	 * this handles the "catch all" and "-default" extension 
	 * but also the normal eMail address.
	 * Code handels also mail addresses with multiple '@' safely.
	 * at = index to last @ sign in mail address
	 * escaped = ldap escaped mailaddress
	 * len = length of escaped mailaddress
	 * i = position of current '-' or '@'
	 */
	done = 0;
	do {
		f = filter_mail(mail->s, &done);
		if (f == (char *)0) die_nomem();

		//log(16, "ldapfilter: '%s'\n", f);

		/* do the search for the email address */
		rv = qldap_lookup(q, f, attrs);
		switch (rv) {
		case OK:
			break; /* something found */
		case TIMEOUT:
			/* temporary error but give up so that the
			 * ldap server can recover */
			die_timeout();
		case TOOMANY:
#ifdef DUPEALIAS
			if (substdio_putflush(subfdout, "K", 1) == -1)
				die_write();
			qldap_free_results(q);
#else
			/* admin error, also temporary */
			temp_fail();
#endif
			return;
		case FAILED:
			/* ... again temporary */
			temp_fail();
			return;
		case NOSUCH:
			break;
		}
	} while (rv != OK && !done);
	/* reset filter_mail */
	filter_mail(0, 0);

	/* nothing found, try a local lookup or a alias delivery */
	if (rv == NOSUCH) {
		/* Sorry, no mailbox here by that name. (#5.1.1) */
		if (substdio_puts(subfdout,
			    "DSorry, no mailbox here by that name. "
			    "(#5.1.1)") == -1)
			die_write();
		if (substdio_putflush(subfdout, "", 1) == -1)
			die_write();
		qldap_free_results(q);
		return;
	}

	/* check if the ldap entry is active */
	rv = qldap_get_status(q, &status);
	if (rv != OK) {
		temp_fail();
		return;
	}
	if (status == STATUS_BOUNCE) {
		/* Mailaddress is administratively disabled. (#5.2.1) */
		if (substdio_puts(subfdout,
			    "DMailaddress is administratively disabled. "
			    "(#5.2.1)") == -1)
			die_write();
		if (substdio_putflush(subfdout, "", 1) == -1)
			die_write();
		qldap_free_results(q);
		return;
	} else if (status == STATUS_DELETE) {
		/* Sorry, no mailbox here by that name. (#5.1.1) */
		if (substdio_puts(subfdout,
			    "DSorry, no mailbox here by that name. "
			    "(#5.1.1)") == -1)
			die_write();
		if (substdio_putflush(subfdout, "", 1) == -1)
			die_write();
		qldap_free_results(q);
		return;
	}

	/* OK */
	if (substdio_putflush(subfdout, "K", 1) == -1)
		die_write();
	qldap_free_results(q);
}

void
cleanup(void)
{
	if (q != 0)
		qldap_free(q);
	q = 0;
}

