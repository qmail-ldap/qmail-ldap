/* auth_pop.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include <errno.h>
#include "error.h"
#include "qldap-errno.h"
#include "readwrite.h"
#include "stralloc.h"
#include "env.h"
#include "str.h"
#include "exit.h"
#include "timeoutread.h"
#include "prot.h"
#include "auth_mod.h"
#include "qmail-ldap.h"
#include "qldap-debug.h"
#ifdef AUTOHOMEDIRMAKE
#include "qldap-mdm.h"
#endif

unsigned int auth_port;

void auth_init(int argc, char **argv, stralloc *login, stralloc *authdata)
/* this function should return the 0-terminated string login and authdata
 * argc and argv are the arguments of the next auth_module. */
{
#define UP_LEN 513
	char up[UP_LEN];
	char *l;
	char *p;
	int  uplen;
	int  i;


	if (!argv[1]) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}

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

	i = 0;
	l = up + i;
	while (up[i++]) if (i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	p = up + i;
	if (i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}
	while (up[i++]) if (i == uplen) {
		qldap_errno = AUTH_NEEDED;
		auth_error();
	}

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
	/* up no longer needed so delete it */
	for ( i=0; i<UP_LEN; up[i++] = 0) ;
	
	auth_port = 110; /* pop3 port */
}

void auth_fail(int argc, char **argv, char *login)
/* Checks if it was a hard fail (bad password) or just a soft error 
 * (user not found) argc and argv are the arguments of the next auth_module. */
{
	/* in the qmail-pop3 chain it is not possible to have multiples 
	 * authentication modules. So lets exit with the correct number ... */
	/* In this case we can use auth_error() */
	auth_error();	
}

void auth_success(int argc, char **argv, char *login, int uid, int gid,
	   			  char* home, char* homedirmake, char *md)
/* starts the next auth_module, or what ever (argv ... ) */
{
	debug(16, "auth_success: login=%s, uid=%u, ", login, uid);
	debug(16, "gid=%u, home=%s, maildir=%s, aliasempty=%s, hdm=%s\n",
			gid, home, md, argv[2], homedirmake );
	
	/* check the uid and the gid */
	if ( UID_MIN > uid || uid > UID_MAX ) {
		debug(2, "warning: auth_success: uid (%u) is to big or small (%u < uid < %u)\n",
				uid, UID_MIN, UID_MAX);
		qldap_errno = AUTH_ERROR;
		auth_error();
	}
	
	if ( GID_MIN > gid || gid > GID_MAX ) {
		debug(2, "warning: auth_success: gid (%u) is to big or small (%u < gid < %u)\n",
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
		 * XXX hard. If you compile with a good compiler this should have the 
		 * XXX same effect or you are probably loosing a few bytes of free mem 
		 */
		if ( homedirmake && *homedirmake ) {
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
	
	debug(32, "auth_success: environment successfully set: USER=%s, HOME=%s, MAILDIR=%s\n",
			login, home, (md && *md)? md:"unset using aliasempty" ); 
	
	/* start qmail-pop3d */
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
	/* Error exit codes:
	 * 1 = error in server configuration
	 * 2 = unable to contact authorization server
	 * 25= user record incorrect
	 * 3 = authorization failed
	 * 4 = account disabled
	 * 5 = mailhost is unreachable
	 * 6 = mailbox is corrupted
	 * 7 = unable to start subprogram
	 * 8 = out of memory
	 */
	debug(2, "warning: auth_error: authorization faild (%s)\n",
		   qldap_err_str(qldap_errno) );

	if ( qldap_errno == LDAP_INIT ) _exit(1);
	if ( qldap_errno == LDAP_BIND ) _exit(2);
	if ( qldap_errno == AUTH_FAILD || qldap_errno == LDAP_REBIND || 
		 qldap_errno == AUTH_NOSUCH ) _exit(3);
	if ( qldap_errno == LDAP_SEARCH || qldap_errno == LDAP_NEEDED ||
		 qldap_errno == ILL_AUTH || qldap_errno == ILL_PATH ) _exit(25);
	if ( qldap_errno == ACC_DISABLED ) _exit(4);
	if ( qldap_errno == BADCLUSTER ) _exit(5);
	if ( qldap_errno == MAILDIR_CORRUPT ) _exit(6);
	if ( qldap_errno == AUTH_EXEC ) _exit(7);
	if ( qldap_errno == ERRNO && errno == error_nomem ) _exit(8);
	_exit(111);
}

static void get_ok(int fd)
/* get the ok for the next command, wait for "+OK.*\r\n" */
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
		len = timeoutread(AUTH_TIMEOUT, fd, ok, OK_LEN);
		if ( len == -1 ) {
			if ( pass == 0 && errno == error_timeout ) {
				pass = 1;
				continue; /* second chance for slow servers */
			}
			qldap_errno = ERRNO;
			auth_error();
		}
		if ( state == 0 ) {
			if ( len != 0 && *ok == '+' ) {
				state = 1;
			} else {
				qldap_errno = BADCLUSTER;
				auth_error();
			}
		}
		for(i = 0; i < len; i++ ) {
			if ( ok[i] == '\n' ) state++;
		}
		if ( pass++ > 2 ) {
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
	write(fd, "user ", 5); write(fd, login, str_len(login) ); write(fd, "\n", 1);
	get_ok(fd);
	write(fd, "pass ", 5); write(fd, passwd, str_len(passwd) ); write(fd, "\n",1);

}
