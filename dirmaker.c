#ifdef AUTOHOMEDIRMAKE
#include <sys/types.h>
#include <unistd.h>

#include "error.h"
#include "control.h"
#include "open.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qlx.h"
#include "stralloc.h"
#include "wait.h"

#include "dirmaker.h"


static stralloc	dirmaker = {0};

int
dirmaker_init(void)
/* ~control/dirmaker SHOULD to be only writeable for root */
{
	if (control_rldef(&dirmaker, "control/dirmaker", 0, "") == -1)
		return -1;
	if (!stralloc_0(&dirmaker))
		return -1;
	log(64, "init: control/dirmaker: %s\n", dirmaker.s);
	return 0;
}

int
dirmaker_make(char *home, char *maildir)
{
	char *(dirargs[3]);
	int child, wstat;

	if (dirmaker.s == 0 || dirmaker.len < 2)
		return MAILDIR_UNCONF;
	
	switch(child = fork()) {
		case -1:
			if (error_temp(errno)) return MAILDIR_FAILED;
			return MAILDIR_HARD;
		case 0:
			dirargs[0] = dirmaker.s; dirargs[1] = home;
			dirargs[2] = maildir; dirargs[3] = 0;
			execvp(*dirargs,dirargs);
			if (error_temp(errno)) _exit(QLX_EXECSOFT);
			_exit(QLX_EXECHARD);
	}

	wait_pid(&wstat,child);
	if (wait_crashed(wstat)) {
		return MAILDIR_CRASHED;
	}
	switch(wait_exitcode(wstat)) {
		case 0:
			return OK;
		case 100: case QLX_EXECHARD:
			return MAILDIR_HARD;
		default:
			return MAILDIR_FAILED;
	}
}
#endif

