/* auth_imap.c for courier-imap */
#include <errno.h>
#include <unistd.h>
#include "alloc.h"
#include "byte.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "fmt.h"
#include "pbsexec.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "scan.h"
#include "sig.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"
#include "timeoutread.h"

#include "auth_mod.h"

#ifndef PORT_IMAP /* this is for testing purposes */
#define PORT_IMAP	143
#endif

const unsigned int auth_port = PORT_IMAP;

#define UP_LEN 1024
static char auth_up[UP_LEN];
static int  auth_uplen;
static int auth_argc;
static char **auth_argv;

void
auth_init(int argc, char **argv, stralloc *login, stralloc *authdata)
{
	char	*a, *s, *t, *l, *p;
	int	i;

	if (argc < 2)
		auth_error(AUTH_CONF);
	if (str_diff(argv[1], "-d") == 0) {
		if (!argv[2])
			auth_error(AUTH_CONF);
		pbstool = argv[2];
		argc -= 2;
		argv += 2;
	}
	if (argc < 2)
		auth_error(AUTH_CONF);
	auth_argc = argc - 1;
	auth_argv = argv + 1;

	a = env_get("AUTHENTICATED");
	if (a && *a) {  /* Already a good guy */
		log(8, "auth_init: allready authenticated\n");
		execvp(*argv, argv);
		auth_error(AUTH_EXEC);
	}
	
#if 0
	/* remove all zombies, why should I do that ??? */
	sig_childdefault();
	while (wait(&waitstat) >= 0) ;
#endif
	for (auth_uplen = 0;;) {
		do {
			i = read(3, auth_up + auth_uplen,
			    sizeof(auth_up) - auth_uplen);
		} while ((i == -1) && (errno == EINTR));
		if (i == -1)
			auth_error(ERRNO);
		if (i == 0) break;
		auth_uplen += i;
		if (auth_uplen >= sizeof(auth_up)) {
			auth_error(PANIC);
		}
	}
	close(3);
	auth_up[auth_uplen] = '\0';
	
	/* get the different fields: service<NL>AUTHTYPE<NL>AUTHDATA */
	i = 0;
	s = auth_up; /* ignore service field */
	while (auth_up[i] && auth_up[i] != '\n' ) i++;
	if (i >= auth_uplen)
		auth_error(NEEDED);
	auth_up[i++] = '\0';
	t = auth_up + i; /* type has to be "login" else fail ... */
	while (auth_up[i] && auth_up[i] != '\n' ) i++;
	if (i >= auth_uplen)
		auth_error(NEEDED);
	auth_up[i++] = '\0';
	if (str_diff("login", t)) {
		/* 
		 * this modul supports only "login"-type,
		 * fail with AUTH_NOSUCH, so the 
		 * next modul is called, perhaps with greater success
		 */
		auth_fail("unknown", AUTH_TYPE);
	}
	l = auth_up + i; /* next login */
	while (auth_up[i] && auth_up[i] != '\n' ) i++;
	if (i >= auth_uplen)
		auth_error(NEEDED);
	auth_up[i++] = '\0';
	p = auth_up + i; /* and the password */
	while (auth_up[i] && auth_up[i] != '\n' ) i++;
	if (i >= auth_uplen)
		auth_error(NEEDED);
	auth_up[i++] = '\0';
	if (i > auth_uplen) /* paranoia */
		auth_error(NEEDED);

	/* copy the login and password into the coresponding structures */
	if (!stralloc_copys(login, l))
		auth_error(ERRNO);
	if (!stralloc_0(login))
		auth_error(ERRNO);

	if (!stralloc_copys(authdata, p))
		auth_error(ERRNO);
	if (!stralloc_0(authdata))
		auth_error(ERRNO);
}

void
auth_fail(const char *login, int reason)
{
	int i;
	int pi[2];
	char *t;
	t = auth_up;
	
	log(2, "warning: auth_fail: user %s failed\n", login);
	if (reason == NOSUCH || reason == AUTH_TYPE) {
		log(4, "warning: auth_fail: %s\n", qldap_err_str(reason));
		if (!env_unset("AUTHENTICATED"))
			auth_error(ERRNO);
		for (i=0; i<auth_uplen; i++) if (!auth_up[i]) auth_up[i] = '\n';
		close(3);
		if (pipe(pi) == -1)
			auth_error(ERRNO);
		if (pi[0] != 3) /* be serious, we closed 3 so ... */
			auth_error(PANIC);
		switch (fork()) {
		case -1:
			auth_error(ERRNO);
		case 0:
			close(pi[1]);
			sig_pipedefault();
			/* start next auth module */
			execvp(*auth_argv, auth_argv);
			auth_error(AUTH_EXEC);
		}
		close(pi[0]);
		while (t) {
			i = write(pi[1],t,auth_uplen);
			if (i == -1) {
				if (errno == error_intr) continue;
				/* note that some data may have been written */
			}
			t += i;
			auth_uplen -= i;
		}
		byte_zero(auth_up, sizeof(auth_up));
		close(pi[1]);
		_exit(0);
	}
	auth_error(reason); /* complete failure */
}

void
auth_success(void)
{
	byte_zero(auth_up, sizeof(auth_up));
	
	/* pop befor smtp */
	pbsexec();
	
	/* start imap process */
	execvp(*auth_argv, auth_argv);

	auth_error(AUTH_EXEC);
	/* end */
}

void auth_error(int errnum)
{
	char envname[FMT_ULONG+8];
	char *env, *n, *n2;
	char **argvs;
	unsigned long numarg, i;
	
	/* XXX under courier-imap it is not simple to give the correct failure
	 * XXX back to the user, perhaps somebody has a good idea */

	byte_zero(auth_up, sizeof(auth_up));
	
	log(2, "warning: auth_error: authorization failed (%s)\n",
		   qldap_err_str(errnum));
	if (!(env = env_get("AUTHARGC")))
		_exit(111);
	scan_ulong(env, &numarg);
	argvs = (char **) alloc((numarg+1) * sizeof(char *));
	n = envname;
	n += fmt_str(n, "AUTHARGV");
	for (i = 0; i < numarg; i++) {
		n2 = n;
		n2 += fmt_ulong(n2, i);
		*n2 = 0;
		if (!(argvs[i] = env_get(envname)))
			_exit(111);
	}
	argvs[i+1] = (char *)0;
#if 0
	/* can no longer find AUTHUSER in authlib(7) of courier-imap 1.7.2 */
	if (!(env = env_get("AUTHUSER")))
		_exit(100);
#endif
	execv(env, argvs);
	_exit(111);
	
}

char *
auth_aliasempty(void)
{
	if (auth_argc > 0)
		return auth_argv[auth_argc-1];
	return (char *)0;
}

#ifdef QLDAP_CLUSTER
static void get_ok(int , const char *);

static void
get_ok(int fd, const char *tag)
/* get the ok for the next command, wait for "[TAG] OK.*\r\n" */
/* This should work (Idea from RFC 1730 and fetchmail) */
{
#define AUTH_TIMEOUT 10 /* 10 sec timeout */
#define OK_LEN 8192+1
	char ok[OK_LEN];
	char *s;
	unsigned char x;
	int  len;
	int  i;

	if (!tag) return; /* bad pointer */
	do {
		len = timeoutread(AUTH_TIMEOUT, fd, ok, sizeof(ok) - 1);
		if (len == -1)
			auth_error(ERRNO);
		ok[len] = '\0';
		/* upper case all */
		for (i = 0, s = ok; i < len; i++) {
			x = *s - 'a';
			if ( x <= 'z' - 'a' ) *s = x + 'A';
			s++;
		}
	} while (str_diffn(ok, tag, str_len(tag)));
	/* tag found, next check for OK */
	s = ok + str_len(tag); /* skip tag */
	while (*s == ' ' || *s == '\t') s++; /* skip all spaces */
	
	if (str_diffn(s, "OK", 2) == 0 ) return;
	else if (str_diffn(s, "BAD", 3) == 0 || str_diffn(s, "NO", 2) == 0)
		/* other server not happy */
		auth_error(BADCLUSTER);
	/* ARRG, this server talks not my dialect */
	auth_error(BADCLUSTER);
}

void
auth_forward(int fd, char *login, char *passwd)
{
	char *tag;
	substdio ss;
	char buf[512];
	
	tag = env_get("IMAPLOGINTAG");
	if (!(tag && *tag))
		/* UH OH, no imap tag, how could that be ? */
		auth_error(PANIC);
	
	get_ok(fd, "*");
	substdio_fdbuf(&ss,write,fd,buf,sizeof(buf));
	substdio_puts(&ss, tag);
	substdio_puts(&ss, " login "); 
	substdio_puts(&ss, login); 
	substdio_puts(&ss, " ");
	substdio_puts(&ss, passwd); 
	substdio_puts(&ss, "\r\n");
	substdio_flush(&ss);
}

#endif /* QLDAP_CLUSTER */

