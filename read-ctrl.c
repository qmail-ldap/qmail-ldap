#include <unistd.h>

#include "auto_qmail.h"
#include "control.h"
#include "error.h"
#include "open.h"

#include "read-ctrl.h"

/* TODO logging */
int
read_controls(ctrlfunc *f)
{
	int	i, fddir;
	
	fddir = open_read(".");
	if (fddir == -1)
		return -1;
	if (chdir(auto_qmail) == -1)
		return -1;
	
	if (control_init() == -1)
		goto fail;
	for (i = 0; f[i] != 0; i++) {
		if (f[i]() == -1)
			goto fail;
	}

	if (fchdir(fddir) == -1)
		return -1;
	close(fddir);
	return 0;
	
fail:
	i = errno;
	if (fchdir(fddir) == -1)
		return -1;
	close(fddir);
	errno = i;
	return -1;
}

