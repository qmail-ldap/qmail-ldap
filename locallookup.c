#include <sys/types.h>
#include <unistd.h>
#include "error.h"
#include "getln.h"
#include "localdelivery.h"
#include "open.h"
#include "passwd.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "substdio.h"

#include "checkpassword.h"
#include "locallookup.h"

/* Edit the first lines in the Makefile to enable local passwd lookups 
 * and debug options.
 * To use shadow passwords under Solaris, uncomment the 'SHADOWOPTS' line 
 * in the Makefile.
 * To use shadow passwords under Linux, uncomment the 'SHADOWOPTS' line and
 * the 'SHADOWLIBS=-lshadow' line in the Makefile.
 */
#include <pwd.h>
#ifdef PW_SHADOW
#include <shadow.h>
#endif
#ifdef AIX
#include <userpw.h>
#endif

int
check_passwd(stralloc *login, stralloc *authdata,
    struct credentials *c, int fast)
{
	int ret;
	struct passwd *pw;
#ifdef PW_SHADOW
	struct spwd *spw;
#endif
#ifdef AIX
	struct userpw *spw;
#endif

	if (localdelivery() == 0) return NOSUCH;

	pw = getpwnam(login->s);
	if (!pw) {
		/* XXX: unfortunately getpwnam() hides temporary errors */
		log(32, "check_passwd: user %s not found in passwd db\n",
		    login->s);
		return NOSUCH;
	}
	if (!fast) {
		c->gid = pw->pw_gid;
		c->uid = pw->pw_uid;
		/*
		 * Here we don't check the home and maildir path, if a user
		 * has a faked passwd entry, then you have a bigger problem
		 * on your system than just a guy how can read the mail of
		 * other users/customers.
		 */
		if (!stralloc_copys(&c->home, pw->pw_dir))
			return ERRNO;
		if (!stralloc_0(&c->home))
			return ERRNO;
	
		ret = get_local_maildir(&c->home, &c->maildir);
		if (ret != 0)
			return ret;
		log(32, "get_local_maildir: maildir=%s\n", c->maildir.s);
	}

#ifdef PW_SHADOW
	spw = getspnam(login->s);
	if (!spw)
		/* XXX: again, temp hidden */
		return FAILED;
	ret = cmp_passwd((unsigned char*) authdata->s, spw->sp_pwdp);
#else /* no PW_SHADOW */
#ifdef AIX
	spw = getuserpw(login->s);
	if (!spw)
		/* XXX: and again */
		return FAILED;
	ret = cmp_passwd((unsigned char*) authdata->s, spw->upw_passwd);
#else /* no AIX */
	ret = cmp_passwd((unsigned char*) authdata->s, pw->pw_passwd);
#endif /* END AIX */
#endif /* END PW_SHADOW */
	log(32, "check_pw: password compare was %s\n", 
	    ret==OK?"successful":"not successful");
	return ret;
}


int
get_local_maildir(stralloc *home, stralloc *maildir)
{
	substdio	ss;
	char		buf[512];
	int		dirfd, fd, match, save;
	
	dirfd = open_read(".");
	if (dirfd == -1)
		return ERRNO;
	if (chdir(home->s) == -1)
		return ERRNO;

	if ((fd = open_read(".qmail")) == -1) {
		if (errno == error_noent) return 0;
		return ERRNO;
	}

	substdio_fdbuf(&ss, read, fd, buf, sizeof(buf));
	while (1) {
		if (getln(&ss, maildir, &match, '\n') != 0) goto tryclose;
		if (!match && !maildir->len) break;
		if ((maildir->s[0] == '.' || maildir->s[0] == '/') && 
			  maildir->s[maildir->len-2] == '/') {
			maildir->s[maildir->len-1] = '\0';
			break;
		}
	}
	if (fchdir(dirfd) == -1)
		return ERRNO;
	close(dirfd);
	close(fd);
	return 0;

tryclose:
	save = errno; /* preserve errno */
	if (fchdir(dirfd) == -1)
		return ERRNO;
	close(dirfd);
	close(fd);
	errno = save;
	return ERRNO;

}


