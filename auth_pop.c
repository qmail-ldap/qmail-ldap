#include <errno.h>
#include <unistd.h>
#include "byte.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "pbsexec.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"
#include "timeoutread.h"

#include "auth_mod.h"

#ifndef PORT_POP3 /* this is for testing purposes */
#define PORT_POP3	110
#endif

const unsigned int auth_port = PORT_POP3;

#define UP_LEN 513
static char auth_up[UP_LEN];
static int auth_argc;
static char **auth_argv;

void
auth_init(int argc, char **argv, stralloc *login, stralloc *authdata)
{
	char	*l, *p;
	int	uplen;
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
	
	for (uplen = 0;;) {
		do {
			i = read(3, auth_up + uplen, sizeof(auth_up) - uplen);
		} while (i == -1 && errno == EINTR);
		if (i == -1)
			auth_error(ERRNO);
		if (i == 0) break;
		uplen += i;
		if (uplen >= sizeof(auth_up))
			auth_error(PANIC);
	}
	close(3);
	auth_up[uplen++] = '\0';
	
	i = 0;
	l = auth_up;
	while (auth_up[i++]) ;
	if (i == uplen)
		auth_error(NEEDED);
	p = auth_up + i;
	while (auth_up[i++]) ;
	if (i == uplen)
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
	log(2, "warning: auth_fail: user %s failed\n", login);
	auth_error(reason);
}

void
auth_success(void)
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
	log(2, "warning: auth_error: authorization failed (%s)\n",
		   qldap_err_str(errnum) );

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
	if (auth_argc > 0)
		return auth_argv[auth_argc-1];
	return (char *)0;
}

#ifdef QLDAP_CLUSTER
static void get_ok(int);

static void get_ok(int fd)
/* get the ok for the next command, wait for "+OK.*\r\n" */
/* This should be a mostly correct solution (adapted from fetchmail) */
{
#define AUTH_TIMEOUT 10 /* 10 sec timeout */
#define OK_LEN 512      /* max length of response (RFC1939) */
	char ok[OK_LEN];
	char *c;
	int  len;
	int  i;

	/* first get one single line from the other pop server */
	len = timeoutread(AUTH_TIMEOUT, fd, ok, OK_LEN);
	if (len == -1) 
		auth_error(ERRNO);
	if (len != 0) {
		c = ok;
		if (*c == '+' || *c == '-')
			c++;
		else
			auth_error(BADCLUSTER);
		for (i = 1; i < len /* paranoia */ && 
				('A' < *c && *c < 'Z') ; ) { i++; c++; }

		if (i < len) {
			*c = '\0';
			if (str_diff(ok, "+OK") == 0)
				return;
			else if ( str_diffn(ok, "-ERR", 4) )
				/* other server is not happy */
				auth_error(BADCLUSTER);
		}
	}
	/* ARRG, very strange POP3 answer */
	auth_error(BADCLUSTER);
}

void auth_forward(int fd, char *login, char *passwd)
{
	char buf[512];
	substdio ss;

	substdio_fdbuf(&ss,write,fd,buf,sizeof(buf));
	get_ok(fd);
	substdio_puts(&ss, "user "); 
	substdio_puts(&ss, login);
	substdio_puts(&ss, "\r\n");
	substdio_flush(&ss);
	get_ok(fd);
	substdio_puts(&ss, "pass "); 
	substdio_puts(&ss, passwd); 
	substdio_puts(&ss, "\r\n");
	substdio_flush(&ss);

}

#endif /* QLDAP_CLUSTER */

