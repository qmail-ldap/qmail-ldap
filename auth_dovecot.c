/*
 * Copyright (c) 2008 Claudio Jeker,
 *      Internet Business Solutions AG, CH-8005 Zürich, Switzerland
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Internet Business
 *      Solutions AG and its contributors.
 * 4. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include <errno.h>
#include <unistd.h>
#include "byte.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "fmt.h"
#include "ip.h"
#include "pbsexec.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "readwrite.h"
#include "scan.h"
#include "sgetopt.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"
#include "timeoutread.h"

#include "checkpassword.h"
#include "auth_mod.h"

#define UP_LEN 513
static char auth_up[UP_LEN];
static int auth_argc;
static char **auth_argv;
static char *aliasempty;

void
auth_setup(struct credentials *c)
{
	static stralloc qenv = {0};
	static stralloc ext = {0};
	char num[FMT_ULONG];
	unsigned long size;

	if (c->size != 0 || c->count != 0) {
		/*
		 * uid and gid are already set. Need to add extra stuff like
		 * quota settings.
		 */
		if (!stralloc_copys(&qenv,"maildir"))
			auth_error(ERRNO);
		if (c->size != 0) {
			if (!stralloc_cats(&qenv,":storage="))
				auth_error(ERRNO);
			size = c->size / 1024;
			if (!stralloc_catb(&qenv, num, fmt_ulong(num, c->size)))
				auth_error(ERRNO);
		}
		if (c->count != 0) {
			if (!stralloc_cats(&qenv, ":messages="))
				auth_error(ERRNO);
			if (!stralloc_catb(&qenv, num,
			    fmt_ulong(num, c->count)))
				auth_error(ERRNO);
		}
		if (!stralloc_0(&qenv))
			auth_error(ERRNO);
		if (!env_put2("userdb_quota_rule", qenv.s))
			auth_error(ERRNO);
		if (!stralloc_copys(&ext,"userdb_quota_rule"))
			auth_error(ERRNO);
		logit(32, "dovecot environment set: userdb_quota_rule %s\n",
		    qenv.s);
	}

	if (c->maildir.s != 0 && c->maildir.s[0] && c->maildir.len > 0) {
		if (ext.s != 0 && ext.len > 0) {
			if (!stralloc_cats(&ext," userdb_mail"))
				auth_error(ERRNO);
		} else {
			if (!stralloc_copys(&ext,"userdb_mail"))
				auth_error(ERRNO);
		}
		if (!stralloc_copys(&qenv,"maildir:"))
			auth_error(ERRNO);
		if (!stralloc_cats(&qenv, c->maildir.s))
			auth_error(ERRNO);
		if (!stralloc_0(&qenv))
			auth_error(ERRNO);
		if (!env_put2("userdb_mail", qenv.s))
			auth_error(ERRNO);
	}

	if (!stralloc_0(&ext))
		auth_error(ERRNO);
	if (!env_put2("EXTRA", ext.s))
		auth_error(ERRNO);
	logit(32, "dovecot environment set: userdb_mail %s\n", qenv.s);
}

void
auth_init(int argc, char **argv, stralloc *login, stralloc *authdata)
{
	extern unsigned long loglevel;
	char		*l, *p;
	unsigned int	uplen, u;
	int		n, opt;

	while ((opt = getopt(argc, argv, "a:d:D:")) != opteof) {
		switch (opt) {
		case 'a':
			aliasempty = optarg;
			break;
		case 'd':
			pbstool = optarg;
			break;
		case 'D':
			scan_ulong(optarg, &loglevel);
			loglevel &= ~256;	/* see auth_mod.c */
			break;
		default:
			auth_error(AUTH_CONF);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		auth_error(AUTH_CONF);
	auth_argc = argc;
	auth_argv = argv;
	
	for (uplen = 0;;) {
		do {
			n = subread(3, auth_up + uplen,
			    sizeof(auth_up) - uplen);
		} while (n == -1 && errno == EINTR);
		if (n == -1)
			auth_error(ERRNO);
		if (n == 0) break;
		uplen += n;
		if (uplen >= sizeof(auth_up))
			auth_error(PANIC);
	}
	close(3);
	auth_up[uplen++] = '\0';
	
	u = 0;
	l = auth_up;
	while (auth_up[u++]) ;
	if (u == uplen)
		auth_error(NEEDED);
	p = auth_up + u;
	while (auth_up[u++]) ;
	if (u == uplen)
		auth_error(NEEDED);

	if (!stralloc_copys(login, l))
		auth_error(ERRNO);
	if (!stralloc_0(login)) 
		auth_error(ERRNO);

	if (!stralloc_copys(authdata, p))
		auth_error(ERRNO);
	if (!stralloc_0(authdata))
		auth_error(ERRNO);

	/* up no longer needed so delete it */
	byte_zero(auth_up, sizeof(auth_up));
}

void
auth_fail(const char *login, int reason)
{
	/* in the qmail-pop3 chain it is not possible to have multiples 
	 * authentication modules. So lets exit with the correct number ... */
	/* In this case we can use auth_error() */
	logit(2, "warning: auth_fail: user %s failed\n", login);
	auth_error(reason);
}

void
auth_success(const char *login)
{
	/* pop befor smtp */
	pbsexec();
	
	/* start qmail-pop3d */
	execvp(*auth_argv,auth_argv);

	auth_error(AUTH_EXEC);
	/* end */
}

void auth_error(int errnum)
{
	/*
	 * See qmail-popup.c for exit codes meanings.
	 */
	logit(2, "warning: auth_error: authorization failed (%s)\n",
		   qldap_err_str(errnum));

	if (errnum == AUTH_CONF) _exit(1);
	if (errnum == TIMEOUT || errnum == LDAP_BIND_UNREACH) _exit(2);
	if (errnum == BADPASS || errnum == NOSUCH) _exit(3);
	if (errnum == NEEDED || errnum == ILLVAL || errnum == BADVAL) _exit(25);
	if (errnum == ACC_DISABLED) _exit(4);
	if (errnum == BADCLUSTER) _exit(5);
	if (errnum == MAILDIR_CORRUPT) _exit(6);
	if (errnum == MAILDIR_FAILED) _exit(61);
	if (errnum == MAILDIR_NONEXIST) _exit(62);
	if (errnum == AUTH_EXEC) _exit(7);
	if (errnum == ERRNO && errno == error_nomem) _exit(8);
	_exit(111);
}

char *
auth_aliasempty(void)
{
	return aliasempty;
}

#ifdef QLDAP_CLUSTER

int
auth_forward(stralloc *host, char *login, char *passwd)
{
	if (!stralloc_0(host)) auth_error(ERRNO);

	/* not to be userdb_ prefixed */
	if (!env_put2("proxy", "1")) auth_error(ERRNO);
	if (!env_put2("host", host->s)) auth_error(ERRNO);
	if (!env_put2("EXTRA", "proxy host")) auth_error(ERRNO);

	auth_success(login);

	return -1;
}

#endif /* QLDAP_CLUSTER */
