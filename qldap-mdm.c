/* qldap-mdm.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "qldap-errno.h"
#include "wait.h"


int make_homedir(char *home, char *maildir, char *dirmaker)
/* executes the file specified with dirmaker returns 0 on success */
/* XXX ~control/dirmaker has to be only at max writeable for root */
{
#ifdef AUTOHOMEDIRMAKE
	/* do the auto homedir creation */
	int child;
	char *(dirargs[3]);
	int wstat;

	switch(child = fork()) {
		case -1:
			qldap_errno = ERRNO;
			return -1;
		case 0:
			dirargs[0] = dirmaker; dirargs[1] = home;
			dirargs[2] = maildir; dirargs[3] = 0;
			execv(*dirargs,dirargs);
			qldap_errno = ERRNO;
			return -1;
	}

	wait_pid(&wstat,child);
	if (wait_crashed(wstat)) {
		qldap_errno = MAILDIR_CRASHED;
		return -1;
	}
	switch(wait_exitcode(wstat)) {
		case 0:
			return 0;
		default:
			qldap_errno = MAILDIR_BADEXIT;
			return -1;
	}
#endif
}

/* XXX the maildirmake stuff is dirictly in qmail-local.c and qmail-pop3d.c
 * XXX this is simpler and better (Perhaps I finde a better way sometimes) ;-) */
/* int make_maildir(...) */
