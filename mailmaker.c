#ifdef AUTOMAILDIRMAKE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include "error.h"
#include "open.h"
#include "qldap-errno.h"

#include "mailmaker.h"

/*
 * XXX the maildirmake stuff is directly in qmail-local.c and qmail-pop3d.c
 * XXX this is simpler and better (Perhaps I'll find a better way sometimes) ;-)
 * XXX BULLSHIT! Simpler and better, was I on drugs? This needs definitifly a 
 * XXX rewrite and while doing that I can also fix the problem with courier.
 */
static int makedir(const char *);

static int
makedir(const char *dir)
{
	struct	stat st;
	
	if (stat(dir, &st) == -1) {
		if (errno == error_noent) {
			if (mkdir(dir,0700) == -1) return ERRNO;
		} else 
			return ERRNO;
	} else if (!S_ISDIR(st.st_mode))
		return MAILDIR_CORRUPT;

	return OK;
}

int
maildir_make(char *maildir)
{
	int	dirfd, oldmask, r, se;

	oldmask = umask(077);
	dirfd = open_read(".");
	if (dirfd == -1)
		return ERRNO;
	if (chdir(maildir) == -1) {
		if ((r = makedir(maildir)) != OK) goto fail;
		if (chdir(maildir) == -1) {
			if (errno == ENOTDIR) {
				r = MAILDIR_CORRUPT;
				goto fail;
			} else {
				r = ERRNO;
				goto fail;
			}
		}
	}
	if ((r = makedir("tmp")) != OK) goto fail;
	if ((r = makedir("cur")) != OK) goto fail;
	if ((r = makedir("new")) != OK) goto fail;

	umask(oldmask);
	if (fchdir(dirfd) == -1) {
		r = ERRNO;
		goto fail;
	}
	close(dirfd);
	return OK;

fail:
	se = errno;
	umask(oldmask);
	fchdir(dirfd);
	close(dirfd);
	errno = se;
	return r;
}
#endif

