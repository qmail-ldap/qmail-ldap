#include <unistd.h>
#include "env.h"
#include "open.h"
#include "qldap-debug.h"
#include "wait.h"

#include "pbsexec.h"

char *pbstool = 0;

void
pbsexec(void)
{
	char *(args[3]);
	int child, wstat;

	if (pbstool == 0 || *pbstool == 0) return;

	if (env_get("NOPBS")) return;

	switch (child = fork()) {
	case -1:
		return;
	case 0:
		/* the pbstool may not read or write to the connection */
		close(0); open_read("/dev/null");
		close(1); open_write("/dev/null");
		close(3);
		
		args[0] = pbstool;
		args[1] = 0;
		execvp(*args, args);
		_exit(111);
	}

	wait_pid(&wstat,child);
	if (wait_crashed(wstat))
		log(2, "pbsexec: %s crashed\n", pbstool);
	else if (wait_exitcode(wstat))
		log(2, "pbsexec: %s failed, exit code %d\n",
		    pbstool, wait_exitcode(wstat));
	else
		log(64, "pbsexec: %s OK\n", pbstool);

	return;
}

