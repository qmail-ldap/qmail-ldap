/* auth_imap.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include "error.h"
#include "qldap-errno.h"
#include "readwrite.h"
#include "stralloc.h"
#include "env.h"
#include "str.h"
#include "exit.h"
#include "timeoutread.h"
#include "fmt.h"
#include "sig.h"
#include "wait.h"
#include "scan.h"
#include "alloc.h"
#include "prot.h"
#include "auth_mod.h"
#include "qmail-ldap.h"
#include "qldap-debug.h"
#ifdef AUTOHOMEDIRMAKE
#include "qldap-mdm.h"
#endif

unsigned int auth_port;
/* those are global defined so that auth_fail can use them */
#define UP_LEN 1024
char up[UP_LEN];
int  uplen;

void auth_init(int argc, char **argv, stralloc *login, stralloc *authdata)
/* this function should return the 0-terminated string login and authdata
 * argc and argv are the arguments of the next auth_module. */
{
	char *s;
	char *t;
	char *l;
	char *p;
	int  i;
	const char *a=env_get("AUTHENTICATED");
	int waitstat;

	if (!argv[1]) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}

	if (a && *a) {  /* Already a good guy */
		debug(8, "auth_init: allready authenticated\n");
		execvp( argv[1],argv + 1);
		qldap_errno = AUTH_EXEC;
		auth_error();
	}
	
	/* remove all zombies */
	sig_childdefault();
	while (wait(&waitstat) >= 0) ;

	uplen = 0;
	for (;;)
	{
		do i = read(3,up + uplen,sizeof(up) - uplen);
		while ((i == -1) && (errno == EINTR));
		if (i == -1) {
			qldap_errno = ERRNO;
			auth_error();
		}
		if (i == 0) break;
		uplen += i;
		if (uplen >= sizeof(up)) {
			qldap_errno = AUTH_PANIC;
			auth_error();
		}
	}
	close(3);

	/* get the different fields: service<NL>AUTHTYPE<NL>AUTHDATA */
	i = 0;
	s = up + i; /* service, for us uninteresting, but we could check for imap */
	while (up[i] && up[i] != '\n' ) if (++i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	if (i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	up[i++] = '\0';
	t = up + i; /* type has to be "login" else fail ... */
	while (up[i] && up[i] != '\n' ) if (++i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	if (i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	up[i++] = '\0';
	if ( str_diff("login", t) ) {
		/* this modul supports only "login"-type, fail with AUTH_NOSUCH, so the 
		 * next modul is called, perhaps with greater success */
		qldap_errno = AUTH_NOSUCH;
		auth_fail(argc, argv, "unknown");
	}
	l = up + i; /* next login */
	while (up[i] && up[i] != '\n' ) if (++i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	if (i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	up[i++] = '\0';
	p = up + i; /* and the password */
	while (up[i] && up[i] != '\n' ) if (++i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	if (i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	up[i++] = '\0';

	/* copy the login and password into the coresponding structures */
	if (!stralloc_copys(login, l) ) {
		qldap_errno = ERRNO;
		auth_error();
	}
	if (!stralloc_0(login) ) {
		qldap_errno = ERRNO;
		auth_error();
	}

	if (!stralloc_copys(authdata, p) ) {
		qldap_errno = ERRNO;
		auth_error();
	}
	if (!stralloc_0(authdata) ) {
		qldap_errno = ERRNO;
		auth_error();
	}

	auth_port = 143; /* imap port */
	
}

void auth_fail(int argc, char **argv, char *login)
/* Checks if it was a hard fail (bad password) or just a soft error (user not found)
   argc and argv are the arguments of the next auth_module. */
{
	int i;
	int pi[2];
	
	debug(2, "warning: auth_fail: user %s faild\n", login);
	if ( qldap_errno == AUTH_NOSUCH ) {
		debug(4, "warning: auth_fail: user %s not found\n", login);
		if ( !env_unset("AUTHENTICATED") ) {
			qldap_errno = ERRNO;
			auth_error();
		}
		for( i=0; i<uplen; i++ ) if ( !up[i] ) { up[i] = '\n'; }
		close(3);
		if (pipe(pi) == -1) {
			qldap_errno = ERRNO;
			auth_error();
		}
		if (pi[0] != 3) { /* be serious, we closed 3 so ... */
			qldap_errno = AUTH_PANIC;
			auth_error();
		}
		switch( fork() ) {
			case -1:
				qldap_errno = ERRNO;
				auth_error();
			case 0:
				close(pi[1]);
				sig_pipedefault();
				execvp( argv[1],argv + 1); /* start next auth module */
				qldap_errno = ERRNO;
				auth_error();
		}
		close(pi[0]);
		while (uplen) {
			i = write(pi[1],up,uplen);
			if (i == -1) {
				if (errno == error_intr) continue;
				/* note that some data may have been written */
			}
			up += i;
			uplen -= i;
		}
		close(pi[1]);
		_exit(0);
	}
	auth_error(); /* complete failure */
}

void auth_success(int argc, char **argv, char *login, int uid, int gid,
	   			  char* home, char* homedirmake, char *md)
/* starts the next auth_module, or what ever (argv ... ) */
{
	debug(16, "auth_success: login=%s, uid=%u, ",
			login, uid);
	debug(16, "gid=%u, home=%s, maildir=%s, aliasempty=%s, hdm=%s\n",
			gid, home, md, argv[2], homedirmake );
	
	/* check the uid and the gid */
	if ( UID_MIN > uid || uid > UID_MAX ) {
		debug(2, 
				"warning: auth_success: uid (%u) is to big or small (%u < uid < %u)\n",
				uid, UID_MIN, UID_MAX);
		qldap_errno = AUTH_ERROR;
		auth_error();
	}
	
	if ( GID_MIN > gid || gid > GID_MAX ) {
		debug(2, 
				"warning: auth_success: gid (%u) is to big or small (%u < gid < %u)\n",
				gid, GID_MIN, GID_MAX);
		qldap_errno = AUTH_ERROR;
		auth_error();
	}

	/* first set the group id */
	if (prot_gid(gid) == -1) {
		qldap_errno = AUTH_ERROR;
		auth_error();
	}
	debug(32, "auth_success: setgid succeded (%i)\n", gid);
	/* ... then the user id */
	if (prot_uid(uid) == -1) {
		qldap_errno = AUTH_ERROR;
		auth_error();
	}
	debug(32, "auth_success: setuid succeded (%i)\n", uid);
	
	/* ... go to home dir and create it if needed */
	if (chdir(home) == -1) {
#ifdef AUTOHOMEDIRMAKE
		/* XXX homedirmake is not everywhere #ifdef'd because this would be too
		 * XXX hard. If you compile with a good compiler this should have the same
		 * XXX effect or you are probably loosing a few bytes of free mem */
		if ( errno == error_noent && homedirmake && *homedirmake ) {
			int ret;
			
			debug(8, "auth_success: makeing homedir with %s %s %s\n",
					homedirmake, home, (md && *md)? md: argv[2] );
			if (md && *md) {
				ret = make_homedir(home, md, homedirmake );
			} else {
				ret = make_homedir(home, argv[2], homedirmake );
			}
			if (ret != 0 ) {
				if ( qldap_errno == ERRNO ) {
					debug(2, "warning: auth_success: dirmaker faild (%s)\n",
							error_str(errno));
				} else {
					debug(2, "warning: auth_success: dirmaker faild (%s)\n",
							qldap_errno == MAILDIR_CRASHED?	"program crashed":
															"bad exit status");
				}
				qldap_errno = MAILDIR_CORRUPT;
				auth_error();
			}
			if (chdir(home) == -1) {
				debug(2, 
						"warning: auth_success: chdir faild after dirmaker (%s)\n",
						error_str(errno));
				qldap_errno = MAILDIR_CORRUPT;
				auth_error();
			}
			debug(32, "auth_success: homedir successfully made\n");
		} else {
#endif
		qldap_errno = MAILDIR_CORRUPT;
		auth_error();
#ifdef AUTOHOMEDIRMAKE
		}
#endif
	}

	/* set up the environment for the execution of qmail-pop3d */
	if (!env_put2("USER",login)) {
		qldap_errno = ERRNO;
		auth_error();
	}
	if (!env_put2("AUTHENTICATED",login)) {
		qldap_errno = ERRNO;
		auth_error();
	}
	if (!env_put2("HOME",home)) {
		qldap_errno = ERRNO;
		auth_error();
	}
	if ( md && *md ) {
		if (!env_put2("MAILDIR",md)) {
			qldap_errno = ERRNO;
			auth_error();
		}
	} else {
		if ( !env_unset("MAILDIR") ) {
		qldap_errno = ERRNO;
			auth_error();
		}
	}
	
	debug(32, 
			"auth_success: environment successfully set: USER=%s, HOME=%s, MAILDIR=%s\n",
			login, home, (md && *md)? md:"unset using aliasempty" ); 
	
	/* ... now check that we are realy not running as root */
	if (!getuid()) {
		qldap_errno = AUTH_ERROR;
		auth_error();
	}
	execvp( argv[1],argv + 1);

	qldap_errno = AUTH_EXEC;
	auth_error();
	/* end */
}

void auth_error(void)
/* error handler for this module, does not return */
{
	char *env;
	char envname[FMT_ULONG+8];
	char *n;
	char *n2;
	unsigned long numarg;
	unsigned long i;
	char **argvs;
	
	/* XXX under courier-imap it is not simple to give the correct failer back
	 * XXX to the user, perhaps somebody has a good idea */

	debug(2, "warning: auth_error: authorization faild (%s)\n",
		   qldap_err_str(qldap_errno) );
	if (! (env = env_get("ARGC") ) ) {
		_exit(111);
	}
	scan_ulong(env, &numarg);
	argvs = (char **) alloc( (numarg+1) * sizeof(char *) );
	n = envname;
	n += fmt_str(n, "AUTHARGV");
	for (i = 0; i < numarg; i++) {
		n2 = n; n2 += fmt_ulong(n2, i); *n2 = 0;
		if (! (argvs[i] = env_get(envname) ) ) {
			_exit(111);
		}
	}
	argvs[i+1] = 0;
	execvp(*argvs, argvs);
	_exit(111);
	
}

static void get_ok(int fd)
/* get the ok for the next command, wait for "\* OK.*\r\n" */
/* XXX this is not the correct solution but should work for 
 * XXX about 99.999...% of the cases */
{
#define AUTH_TIMEOUT 10 /* 10 sec timeout */
#define OK_LEN 128
	char ok[OK_LEN];
	int  len;
	int  i;
	int  pass;
	int  state;

	pass = 0;
	state = 0;
	do {
		len = timeoutread(AUTH_TIMEOUT, fd, ok + len, sizeof(ok) - len);
		if ( len == -1 ) {
			if ( pass == 0 && errno == error_timeout ) {
				pass = 1;
				continue; /* second chance for slow servers */
			}
			qldap_errno = ERRNO;
			auth_error();
		}
		if ( state == 0 ) {
			if ( len != 0 && ok[0] == '*' ) {
				if (len > 4 && ok[2] == 'O' && ok[3] == 'K' ) {
					state = 1;
				} else if ( len > 4 ){
					qldap_errno = BADCLUSTER;
					auth_error();
				} else {
					pass++;
					continue;
				}
			} else {
				qldap_errno = BADCLUSTER;
				auth_error();
			}
		}
		for(i = 0; state == 1 && i < len; i++ ) {
			if ( ok[i] == '\n' ) state++;
		}
		if ( pass++ > 10 ) {
			qldap_errno = BADCLUSTER;
			auth_error();
		}
	} while( state != 2 );
}

void auth_forward(int fd, char *login, char *passwd)
/* for connection forwarding, makes the login part and returns after sending the
 * latest command immidiatly */
{
	get_ok(fd);
	write(fd, "* login ", 5); write(fd, login, str_len(login) ); write(fd, " ", 1);
	write(fd, passwd, str_len(passwd) ); write(fd, "\n",1);
	get_ok(fd);

}
