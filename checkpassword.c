#include <sys/types.h>
#include <unistd.h>
#include "auth_mod.h"
#include "auto_uids.h"
#include "byte.h"
#include "check.h"
#include "env.h"
#include "error.h"
#include "fmt.h"
#include "locallookup.h"
#include "passwd.h"
#include "pbsexec.h"
#include "prot.h"
#include "qldap.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "scan.h"
#include "str.h"
#include "stralloc.h"

#ifdef QLDAP_CLUSTER
#include <sys/socket.h>
#include "dns.h"
#include "ipalloc.h"
#include "ipme.h"
#include "ndelay.h"
#include "qldap-cluster.h"
#include "select.h"
#include "timeoutconn.h"
#endif
#ifdef AUTOHOMEDIRMAKE
#include "dirmaker.h"
#endif
#ifdef AUTOMAILDIRMAKE
#include "mailmaker.h"
#endif

#include "checkpassword.h"

int (*checkfunc[])(stralloc *, stralloc *, struct credentials *, int) = {
	check_ldap,
	check_passwd,
	0
};

int
check(stralloc *login, stralloc *authdata, struct credentials *c, int fast)
{
	int	i, r;

	for (i = 0; checkfunc[i] != 0; i++)
		switch (r = checkfunc[i](login, authdata, c, fast)) {
		case OK:
		case FORWARD:
			return r;
		case NOSUCH:
			/* lets try an other backend */
			break;
		case BADPASS:
			/* NOTE: users defined in two dbs are not allowed */
			return BADPASS;
		default:
			return r;
		}
	
	return NOSUCH;
}

int
check_ldap(stralloc *login, stralloc *authdata,
    struct credentials *c, int fast)
{
	static	stralloc ld = {0};
	qldap	*q;
	char	*filter;
	int	r, status, pwok;
	const	char	*attrs[] = {
				LDAP_UID, /* the first 6 attrs are default */
				LDAP_QMAILUID,
				LDAP_QMAILGID,
				LDAP_ISACTIVE,
				LDAP_MAILHOST,
				LDAP_MAILSTORE,
				LDAP_HOMEDIR,
				LDAP_PASSWD, 0}; /* passwd is extra */

	/* TODO more debug output is needed */
	q = qldap_new();
	if (q == 0)
		return ERRNO;
	
	r = qldap_open(q);
	if (r != OK) goto fail;
	r = qldap_bind(q, 0, 0);
	if (r != OK) goto fail;
	
	if (fast) {
		/* just comapre passwords and account status */
		attrs[0] = LDAP_ISACTIVE;
		if (qldap_need_rebind() == 0) {
			attrs[1] = LDAP_PASSWD;
			attrs[2] = 0;
		} else
			attrs[1] = 0;
	} else {
		if (qldap_need_rebind() != 0)
			attrs[7] = 0;
	}

	filter = filter_uid(login->s);
	if (filter == 0) { r = ERRNO; goto fail; }

	r = qldap_lookup(q, filter, attrs);
	if (r != OK) goto fail;

	r = qldap_get_status(q, &status);
	if (r != OK) goto fail;
	if (status == STATUS_BOUNCE || status == STATUS_NOPOP) {
		qldap_free(q);
		return ACC_DISABLED;
	}
	
	if (!fast) {
#ifdef QLDAP_CLUSTER
		r = qldap_get_attr(q, LDAP_MAILHOST, &c->forwarder,
		    SINGLE_VALUE);
		if (r != OK && r != NOSUCH) goto fail;
		if (r == OK && cluster(c->forwarder.s) == 1) {
			/* hostname is different, so I reconnect */
			log(8, "check_ldap: forwarding session to %s\n",
			    c->forwarder.s);
			pwok = FORWARD;
		}
#endif

		r = qldap_get_uid(q, &c->uid);
		if (r != OK) goto fail;
		r = qldap_get_gid(q, &c->gid);
		if (r != OK) goto fail;
		r = qldap_get_mailstore(q, &c->home, &c->maildir);
		if (r != OK) goto fail;
		size = count = max = 0;
		r = qldap_get_quota(q, &size, &count, &max);
		if (r != OK) goto fail;
		if (max != 0) {
			num[fmt_ulong(num, max)] = 0;
			if (!env_put2("DATASIZE", num))
				auth_error(ERRNO);
		}
		if (size != 0 || count != 0) {
			if (size != 0) {
				if (!stralloc_copyb(&ld, num,
					    fmt_ulong(num, size)))
					auth_error(ERRNO);
				if (!stralloc_append(&ld, "S"))
					auth_error(ERRNO);
			}
			if (count != 0) {
				if (size != 0)
					if (!stralloc_append(&ld, ","))
						auth_error(ERRNO);
				if (!stralloc_copyb(&ld, num,
					    fmt_ulong(num, count)))
					auth_error(ERRNO);
				if (!stralloc_append(&ld, "C"))
					auth_error(ERRNO);
			}
			if (!stralloc_0(&ld)) auth_error(ERRNO);
			if (!env_put2(ENV_QUOTA, ld.s )) auth_error(ERRNO);
		}
	}
	
	if (qldap_need_rebind() == 0) {
		r = qldap_get_attr(q, LDAP_PASSWD, &ld, SINGLE_VALUE);
		if (r != OK) goto fail;
		pwok = cmp_passwd(authdata->s, ld.s);
	} else {
		r = qldap_get_dn(q, &ld);
		if (r != OK) goto fail;
		r = qldap_rebind(q, ld.s, authdata->s);
		switch (r) {
		case OK:
			pwok = OK;
			break;
		case LDAP_BIND_AUTH:
			pwok = BADPASS;
			break;
		default:
			pwok = r;
			break;
		}
	}

	log(32, "check_ldap: password compare was %s\n", 
	    pwok == OK || pwok == FORWARD ?
	    "successful":"not successful");
	qldap_free(q);
	return pwok;
fail:
	qldap_free(q);
	return r;
	
}

void
change_uid(int uid, int gid)
{
	int	id;
	
	id = geteuid();
	if (id != 0 && (id == uid || id == -1)) {
		/* not running as root so return */
		log(32, "change_uid: already running non root\n");
		return;
	}
	if (uid == -1 && gid == -1) {
		/* run as non-privileged user qmaild group nofiles */
		uid = auto_uidd;
		gid = auto_gidn;
	}
	/* first set the group id */
	if (prot_gid(gid) == -1)
		auth_error(ERRNO);
	log(32, "setgid succeeded (%i)\n", gid);
	
	/* ... then the user id */
	if (prot_uid(uid) == -1)
		auth_error(ERRNO);
	log(32, "setuid succeeded (%i)\n", uid);
	
	/* ... now check that we are realy not running as root */
	if (!getuid())
		auth_error(FAILED);
}

void
setup_env(char *user, struct credentials *c)
{
	/* set up the environment for the execution of the subprogram */
	if (!env_put2("USER", user))
		auth_error(ERRNO);
	
	/* only courier-imap needs this but we set it anyway */
	if (!env_put2("AUTHENTICATED", user))
		auth_error(ERRNO);
	
	if (!env_put2("HOME", c->home.s))
		auth_error(ERRNO);
	
	if (c->maildir.s != 0 && c->maildir.len > 0) {
		if (!env_put2("MAILDIR", c->maildir.s))
			auth_error(ERRNO);
	} else {
		if (!env_unset("MAILDIR"))
			auth_error(ERRNO);
	}
	log(32, "environment successfully set: "
	    "USER %s, HOME %s, MAILDIR %s\n",
	    user, c->home.s,
	    c->maildir.s != 0 && c->maildir.len > 0?
	    c->maildir.s:"unset, using aliasempty"); 
}

void
chdir_or_make(char *home, char *maildir)
{
	char	*md;

	if (maildir == (char *)0)
		md = auth_aliasempty();
	else
		md = maildir;

	/* ... go to home dir and create it if needed */
	if (chdir(home) == -1) {
#ifdef AUTOHOMEDIRMAKE
		log(8, "makeing homedir for %s %s\n", home, md);
			
		switch (dirmaker_make(home, md)) {
		case OK:
			break;
		case MAILDIR_CRASHED:
			log(2, "warning: dirmaker failed: program crashed\n");
			auth_error(MAILDIR_FAILED);
		case MAILDIR_FAILED:
			log(2, "warning: dirmaker failed: bad exit status\n");
			auth_error(MAILDIR_FAILED);
		case MAILDIR_UNCONF:
			log(2, "warning: dirmaker failed: not configured\n");
			auth_error(MAILDIR_NONEXIST);
		case MAILDIR_HARD:
			log(2, "warning: dirmaker failed: hard error\n");
		case ERRNO:
		default:
			log(2, "warning: dirmaker failed (%s)\n",
			    error_str(errno));
			auth_error(MAILDIR_FAILED);
		}
		if (chdir(home) == -1) {
			log(2, "warning: 2nd chdir failed: %s\n",
			    error_str(errno));
			auth_error(MAILDIR_FAILED);
		}
		log(32, "homedir successfully made\n");
#else
		log(2, "warning: chdir failed: %s\n", error_str(errno));
		auth_error(MAILDIR_NONEXIST);
#endif
	}
#ifdef AUTOMAILDIRMAKE
	switch (maildir_make(md)) {
	case OK:
		break;
	case MAILDIR_CORRUPT:
		log(2, "warning: maildir_make failed (%s)\n",
		    "maildir seems to be corrupt");
		auth_error(MAILDIR_CORRUPT);
	case ERRNO:
	default:
		log(2, "warning: maildir_make failed (%s)\n",
		    error_str(errno));
		auth_error(MAILDIR_FAILED);
	}
#endif
}

#ifdef QLDAP_CLUSTER
static int allwrite(int (*)(),int, char *,int);
static void copyloop(int, int, int);
static char copybuf[4096];

static int
allwrite(int (*op)(),int fd, char *buf,int len)
{
	int	w;

	while (len) {
		w = op(fd,buf,len);
		if (w == -1) {
			if (errno == error_intr) continue;
			return -1;
		}
		if (w == 0) ; /* luser's fault */
		buf += w;
		len -= w;
	}
	return 0;
}

static void
copyloop(int infd, int outfd, int timeout)
{
	fd_set	iofds;
	struct	timeval tv;
	int	maxfd;	/* Maximum numbered fd used */
	int	bytes, ret, in, out;

	in = 1; out = 1;
	ndelay_off(infd); ndelay_off(outfd);
	while (in || out) {
		/* file descriptor bits */
		FD_ZERO(&iofds);
		maxfd = -1;
		if (in) {
			FD_SET(infd, &iofds);
			if (infd > maxfd)
				maxfd = infd;
		}
		if (out) {
			FD_SET(outfd, &iofds);
			if (outfd > maxfd)
				maxfd = outfd;
		}
		/* Set up timeout */
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		ret = select(maxfd + 1, &iofds, (fd_set *)0, (fd_set *)0, &tv);
		if (ret == -1) {
			log(1, "copyloop: select failed %s\n",
			    error_str(errno));
			break;
		} else if (ret == 0) {
			log(32, "copyloop: select timeout\n");
			break;
		}
		if(in && FD_ISSET(infd, &iofds)) {
			if((bytes = read(infd, copybuf,
					    sizeof(copybuf))) < 0) {
				log(1, "copyloop: read failed: %s\n",
				    error_str(errno));
				break;
			}
			if (bytes == 0) {
				/* close recv end on in and ...
				   close send 'end' on out */
				shutdown(infd, 0);
				shutdown(outfd, 1);
				in = 0; /* do no longer select on infd */
			} else if(allwrite(write, outfd, copybuf, bytes) != 0) {
				log(1, "copyloop: write out failed: %s\n",
				    error_str(errno));
				break;
			}
		}
		if(out && FD_ISSET(outfd, &iofds)) {
			if((bytes = read(outfd, copybuf,
					    sizeof(copybuf))) < 0) {
				log(1, "copyloop: read failed: %s\n",
				    error_str(errno));
				break;
			}
			log(32, "copyloop: read in %i bytes read\n", bytes);
			if (bytes == 0) {
				/* close recv end on out and ...
				   close send 'end' on in */
				shutdown(outfd, 0);
				shutdown(infd, 1);
				out = 0; /* do no longer select on outfd */
			} else if(allwrite(write, infd, copybuf, bytes) != 0) {
				log(1, "copyloop: write in failed: %s\n",
				    error_str(errno));
				break;
			}
		}
	}
	close(infd);
	close(outfd);
	return;
}

void
forward(char *name, char *passwd, struct credentials *c)
{
	struct	ip_address outip;
	ipalloc	ip = {0};
	int	ffd;
	int	timeout = 31*60; /* ~30 min timeout RFC1730 */
	int	ctimeout = 30;
	
	/* pop befor smtp */
	pbsexec();

	if (!ip_scan("0.0.0.0", &outip))
		auth_error(ERRNO);

	dns_init(0);
	switch (dns_ip(&ip,&c->forwarder)) {
		case DNS_MEM:
			auth_error(ERRNO);
		case DNS_SOFT:
		case DNS_HARD:
			auth_error(BADCLUSTER);
		case 1:
			if (ip.len <= 0)
				auth_error(BADCLUSTER);
	}
	/* 
	   20010523 Don't check if only one IP is returned, so it is
	   possible to have a cluster node consisting of multiple machines. 
	   XXX If your mailhost is bad (bad entries in ldap) you will get
	   bad loops, the only limit is the tcpserver concurrency limit.
	   20030627 Could we use the ipme stuff of qmail-remote, to make
	   single hop loops impossible? Let's try it.
	 */
	if (ipme_is(&ip.ix[0].ip) == 1)
		auth_error(BADCLUSTER);

	ffd = socket(AF_INET, SOCK_STREAM, 0);
	if (ffd == -1)
		auth_error(ERRNO);
	
	if (timeoutconn(ffd, &ip.ix[0].ip, &outip, auth_port, ctimeout) != 0)
		auth_error(ERRNO);
	
	/* We have a connection, first send user and pass */
	auth_forward(ffd, name, passwd);
	copyloop(0, ffd, timeout);

	_exit(0); /* all went ok, exit normaly */
}

#endif /* QLDAP_CLUSTER */

