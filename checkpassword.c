/* checkpasswd.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "qmail-ldap.h"
#include "stralloc.h"
#include "auth_mod.h"
#include "qldap-ldaplib.h"
#include "qldap-errno.h"
#include "readwrite.h"
#include "error.h"
#include "str.h"
#include "open.h"
#include "substdio.h"
#include "getln.h"
#include <sys/types.h>
#include <sys/socket.h>
#include "compatibility.h"
#include "digest_md4.h"
#include "digest_md5.h"
#include "digest_rmd160.h"
#include "digest_sha1.h"
#include "select.h"
#include "ipalloc.h"
#include "dns.h"
#include "timeoutconn.h"
#include "byte.h"
#include "scan.h"
#include "fmt.h"
#include "alloc.h"
#include <assert.h>
#include "check.h"
#include "qldap-debug.h"

/* Edit the first lines in the Makefile to enable local passwd lookups and debug options.
 * To use shadow passwords under Solaris, uncomment the 'SHADOWOPTS' line in the Makefile.
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

extern stralloc qldap_me;

int rebind; 
int cluster;

static int check_ldap(stralloc *login,
	   				  stralloc *authdata,
					  unsigned long *uid,
					  unsigned long *gid,
					  stralloc *home);

static int check_passwd(stralloc *login,
	   					stralloc *authdata,
						unsigned long *uid,
						unsigned long *gid,
						stralloc *home,
						stralloc *md);

static int cmp_passwd(char *clear, char *encrypted);

static int get_local_maildir(stralloc *home, stralloc *maildir);

static void copyloop(int infd, int outfd, int timeout);

#ifdef QLDAP_CLUSTER
static void forward_session(char *host, char *name, char *passwd);
#endif

static char* make_filter(stralloc *value);
static void free_filter(char* filter);

void main(int argc, char **argv)
{
	int locald;
	stralloc login = {0};
	stralloc authdata = {0};
	stralloc home = {0};
	stralloc homemaker = {0};
	stralloc maildir = {0};
	unsigned long uid;
	unsigned long gid;

	init_debug(STDERR, 64); /* XXX limited to 64 so it is not possible to get
							 * XXX passwords via debug under normal systems */

	auth_init(argc, argv, &login, &authdata);
	debug(128, "auth_init: login=%s, authdata=%s\n", login.s, authdata.s);
	
	if ( init_ldap(&locald, &cluster, &rebind, &homemaker, 0, 0, 0) == -1 ) {
		debug(1, "alert: init_ldap faild.\n");
		_exit(1);
	}
	debug(64, "init_ldap: ld=%i, cluster=%i, rebind=%i, hdm=%s\n", 
			locald, cluster, rebind, homemaker.s);
	
	if ( check_ldap(&login, &authdata, &uid, &gid, &home) ) {
		debug(16, "authentication with ldap was not successful\n");
		if ( locald == 1 && qldap_errno == LDAP_NOSUCH ) {
			debug(16, "trying to authenticate with the local passwd db\n");
			if ( check_passwd(&login, &authdata, &uid, &gid, &home, &maildir) ) {
				auth_fail(argc, argv, login.s);
			}
		} else {
			auth_fail(argc, argv, login.s);
		}
	}
	
	auth_success(argc, argv, login.s, uid, gid, home.s, homemaker.s, maildir.s);
	_exit(1); /* should never get here */
}

int check_ldap(stralloc *login, stralloc *authdata, unsigned long *uid, 
			   unsigned long *gid, stralloc *home)
{
	userinfo	info;
	extrainfo	extra[2];
	searchinfo	search;
	int		ret;
	char    *attrs[] = { LDAP_UID, /* the first 5 attrs are the default ones */
						 LDAP_QMAILUID,
						 LDAP_QMAILGID,
						 LDAP_ISACTIVE,
						 LDAP_MAILHOST,
						 LDAP_MAILSTORE,
						 LDAP_PASSWD, 0 }; /* passwd is extra */

	/* initalize the different info objects */
	if ( rebind ) {
		extra[0].what = 0;	/* under rebind mode no additional info is needed */
		search.bindpw = authdata->s;	/* rebind on, check passwd via ldap rebind */ 
	} else {
		extra[0].what = LDAP_PASSWD; /* need to get the crypted password */
		search.bindpw = 0; 	/* rebind off */
	}
	extra[1].what = 0;		/* end marker for extra info */
	
	search.filter = make_filter(login);	/* create search filter */
	
	ret = ldap_lookup(&search, attrs, &info, extra);
	free_filter(search.filter);	/* free the old filter */
	if ( ret != 0 ) {
		debug(4, "warning: check_ldap: ldap_lookup not successful!\n");
		return -1;
	}
	/* check the status of the account !!! */
	if ( info.status == STATUS_BOUNCE || info.status == STATUS_NOPOP ) {
		qldap_errno = ACC_DISABLED;
		return -1;
	}
	
#ifdef QLDAP_CLUSTER
	/* for cluster check if I'm on the right host */
	if ( cluster && info.host && str_diff(qldap_me.s, info.host) ) {
		/* hostname is different, so I reconnect */
		debug(8, "check_ldap: forwarding session to %s\n", info.host);
		forward_session(info.host, login->s, authdata->s);
		/* that's it. Function does not return */ 
	}
#endif

	scan_ulong(info.uid, uid);	/* get uid, gid and home */
	scan_ulong(info.gid, gid);	/* the values are checked later */
	if ( ! stralloc_copys(home, info.mms) ) {	/* ... the same for the path */
		qldap_errno = ERRNO;
		return -1;
	}
	/* lets check the home path for his correctnes (no ../ and special chars) because 
	 * the ldap-server could be returning fake entries (modified by a "hacker") 
	 * There is still the possibility that one customer changes his mailmessagestore to
	 * point to an other user/customer so don't let user/customer modifiy the 
	 * mailmassagestore, uid, qmailUID, qmailGID ... */
	if ( !chck_pathb(home->s,home->len) ) {
		debug(2, "warning: check_ldap: path contains illegal chars!\n");
		qldap_errno = ILL_PATH;
		return -1;
	}
	if (!stralloc_0(home) ) {
		qldap_errno = ERRNO;
		return -1;
	}
	/* free a part of the info struct */
	alloc_free(info.user);
	alloc_free(info.uid);
	alloc_free(info.gid);
	alloc_free(info.mms);
	
	if ( rebind && search.bind_ok ) {
		debug(32, 
				"check_ldap: ldap_lookup sucessfully authenticated with rebind\n");
		return 0; /* if we got till here under rebind mode, the user is authenticated */
	} else if ( rebind ) {
		debug(32, 
				"check_ldap: ldap_lookup not sucessfully authenticated with rebind\n");
		qldap_errno = AUTH_FAILD;
		return -1; /* user authentification faild */
	}
	
	if ( ! extra[0].vals ) {
		debug(2, "warning: check_ldap: password is missing for uid %s\n", login);
		qldap_errno = AUTH_NEEDED;
		return -1; 
	}
	
	ret = cmp_passwd(authdata->s, extra[0].vals[0]); 
	debug(32, "check_ldap: password compare was %s\n", 
			ret==0?"successful":"not successful");
	ldap_value_free(extra[0].vals);
	return ret;
}

static int check_passwd(stralloc *login, stralloc *authdata, unsigned long *uid, 
				 unsigned long *gid, stralloc *home, stralloc *md)
{
	int ret;
	struct passwd *pw;
#ifdef PW_SHADOW
	struct spwd *spw;
#endif
#ifdef AIX
	struct userpw *spw;
#endif
	
	pw = getpwnam(login->s);
	if (!pw) {
		/* XXX: unfortunately getpwnam() hides temporary errors */
		debug(32, "check_passwd: user %s not found in passwd db\n", login->s);
		qldap_errno = AUTH_NOSUCH;
		return -1;
	}
	*gid = pw->pw_gid;
	*uid = pw->pw_uid;

	/* here we don't check the home and maildir path, if a user has a faked passwd
	 * entry, then you have a bigger problem on your system than just a guy how can
	 * read the mail of other users/customers */
	if (!stralloc_copys(home, pw->pw_dir) ) {
		qldap_errno = ERRNO;
		return -1;
	}
	
	if ( get_local_maildir(home, md) == -1 ) {
		/* function sets qldap_errno */
		return -1;
	}
	debug(32, "get_local_maildir: maildir=%s\n", md->s);
	
	if (!stralloc_0(home) ) {
		qldap_errno = ERRNO;
		auth_error();
	}
	
#ifdef PW_SHADOW
	spw = getspnam(login->s);
	if (!spw) {
		/* XXX: again, temp hidden */
		qldap_errno = AUTH_ERROR;
		return -1;
	}
	ret = cmp_passwd(authdata->s, spw->sp_pwdp);
#else /* no PW_SHADOW */
#ifdef AIX
	spw = getuserpw(login->s);
	if (!spw) {
		/* XXX: and again */
		qldap_errno = AUTH_ERROR;
		return -1;
	}
	ret = cmp_passwd(authdata->s, spw->upw_passwd);
#else /* no AIX */
	ret = cmp_passwd(authdata->s, pw->pw_passwd);
#endif /* END AIX */
#endif /* END PW_SHADOW */
	debug(32, "check_pw: password compare was %s\n", 
			ret==0?"successful":"not successful");
	return ret;
	
}

static int cmp_passwd(char *clear, char *encrypted)
{
#define HASH_LEN 100 /* is this enough, I think yes *//* What do you think ? */
	char hashed[HASH_LEN];
	char salt[33];
	int  shift;
	
	if (encrypted[0] == '{') { /* hashed */
		if (!str_diffn("{crypt}", encrypted, 7) ) {
			/* CRYPT */
			shift = 7;
			str_copy(hashed, crypt(clear, encrypted+shift) );
		} else if (!str_diffn("{MD4}", encrypted, 5) ) {
			/* MD4 */
			shift = 5;
			MD4DataBase64(clear, strlen(clear), hashed, sizeof(hashed));
		} else if (!str_diffn("{MD5}", encrypted, 5) ) {
			/* MD5 */
			shift = 5;
			MD5DataBase64(clear, strlen(clear), hashed, sizeof(hashed));
		} else if (!str_diffn("{NS-MTA-MD5}", encrypted, 12) ) {
			/* NS-MTA-MD5 */
			shift = 12;
			if (!strlen(encrypted) == 76) {
				qldap_errno = ILL_AUTH;
				return -1;
			} /* boom */
			byte_copy(salt, 32, &encrypted[44]);
			salt[32] = 0;
			ns_mta_hash_alg(hashed, salt, clear);
			byte_copy(&hashed[32], 33, salt);
		} else if (!str_diffn("{SHA}", encrypted, 5) ) {
			/* SHA */
			shift = 5;
			SHA1DataBase64(clear, strlen(clear), hashed, sizeof(hashed));
		} else  if (!str_diffn("{RMD160}", encrypted, 8) ) {
			/* RMD160 */
			shift = 8;
			RMD160DataBase64(clear, strlen(clear), hashed, sizeof(hashed));
		} else {
			/* unknown hash function detected */ 
			shift = 0;
			qldap_errno = ILL_AUTH;
			return -1;
		}
		/* End getting correct hash-func hashed */
		debug(128, "cpm_passwd: comparing hashed passwd (%s == %s)\n", 
				hashed, encrypted);
		if (!*encrypted || str_diff(hashed,encrypted+shift) ) {
			qldap_errno = AUTH_FAILD;
			return -1;
		}
		/* hashed passwds are equal */
	} else { /* crypt or clear text */
		debug(128, "cpm_passwd: comparing standart passwd (%s == %s)\n", 
				crypt(clear,encrypted), encrypted);
		if (!*encrypted || str_diff(encrypted, crypt(clear,encrypted) ) ) {
			/* CLEARTEXTPASSWD ARE NOT GOOD */
#ifdef CLEARTEXTPASSWD
			if (!*encrypted || str_diff(encrypted, clear) ) {
#endif
			qldap_errno = AUTH_FAILD;
			return -1;
#ifdef CLEARTEXTPASSWD
			}
#endif
			/* crypted or cleartext passwd ok */
		}
	} /* end -- hashed or crypt/clear text */

	return 0;

}

static int get_local_maildir(stralloc *home, stralloc *maildir)
{
	substdio ss;
	stralloc dotqmail = {0};
	char buf[512];
	int match;
	int fd;
	
	if ( ! stralloc_copy(&dotqmail, home) ) {
		qldap_errno = ERRNO;
		return -1;
	}
	if ( ! stralloc_cats(&dotqmail, "/.qmail") ) {
		qldap_errno = ERRNO;
		return -1;
	}
	if ( ! stralloc_0(&dotqmail) ) {
		qldap_errno = ERRNO;
		return -1;
	}
	
	if ( ( fd = open_read(dotqmail.s) ) == -1 ) {
		if ( errno == error_noent ) return 0;
		qldap_errno = ERRNO;
		return -1;
	}
	substdio_fdbuf(&ss,read,fd,buf,sizeof(buf));
	while (1) {
		if (getln(&ss,&dotqmail,&match,'\n') != 0) goto tryclose;
		if (!match && !dotqmail.len) break;
		if ( (dotqmail.s[0] == '.' || dotqmail.s[0] == '/') && 
			  dotqmail.s[dotqmail.len-2] == '/' ) { /* is a maildir line ? */
			if ( ! stralloc_copy(maildir, &dotqmail) ) goto tryclose;
			maildir->s[maildir->len-1] = '\0';
			break;
		}		
	}
	
	close(fd);
	if ( ! stralloc_copys(&dotqmail, "") ) {
		qldap_errno = ERRNO;
		return -1;
	}
	return 0;

tryclose:
	match = errno; /* preserve errno */
	close(fd);
	errno = match;
	qldap_errno = ERRNO;
	return -1;

}

static void copyloop(int infd, int outfd, int timeout)
{
	fd_set iofds;
	fd_set savedfds;
	int maxfd;			/* Maximum numbered fd used */
	struct timeval tv;
	unsigned long bytes;
	char buf[4096];		/* very big buffer ethernet pkgs are only 1500 bytes long */

	/* Set up timeout */
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	/* file descriptor bits */
	FD_ZERO(&savedfds);
	FD_SET(infd, &savedfds);
	FD_SET(outfd, &savedfds);

	if (infd > outfd) {
		maxfd = infd;
	} else {
		maxfd = outfd;
	}

	while(1) {
		byte_copy(&iofds, sizeof(iofds), &savedfds);

		if ( select( maxfd + 1, &iofds, (fd_set *)0, (fd_set *)0, &tv) <= 0 ) {
			break;
		}

		if(FD_ISSET(infd, &iofds)) {
			if((bytes = read(infd, buf, sizeof(buf))) <= 0)
				break;
			if(write(outfd, buf, bytes) != bytes)
				break;
		}
		if(FD_ISSET(outfd, &iofds)) {
			if((bytes = read(outfd, buf, sizeof(buf))) <= 0)
				break;
			if(write(infd, buf, bytes) != bytes)
				break;
		}
	}

	shutdown(infd,0);
	shutdown(outfd,0);
	close(infd);
	close(outfd);
	return;
}

static void forward_session(char *host, char *name, char *passwd)
{
	ipalloc ip = {0};
	stralloc host_stralloc = {0};
	int ffd;
	int timeout = 60;
	int ctimeout = 20;
	
	if (!stralloc_copys(&host_stralloc, host)) {
		qldap_errno = ERRNO;
		auth_error();
	}

	switch (dns_ip(&ip,&host_stralloc)) {
		case DNS_MEM:
			qldap_errno = ERRNO;
			auth_error();
		case DNS_SOFT:
			qldap_errno = BADCLUSTER;
			auth_error();
		case DNS_HARD:
			qldap_errno = BADCLUSTER;
			auth_error();
		case 1:
			if (ip.len <= 0) {
				qldap_errno = BADCLUSTER;
				auth_error();
			}
	}
	if ( ip.len != 1 ) {
		qldap_errno = BADCLUSTER;
		auth_error();
	}
	
	ffd = socket(AF_INET,SOCK_STREAM,0);
	if (ffd == -1) {
		qldap_errno = ERRNO;
		auth_error();
	}
	
	if (timeoutconn(ffd, &ip.ix[0].ip, auth_port, ctimeout) != 0) {
		qldap_errno = ERRNO;
		auth_error();
	}
	
	/* We have a connection, first send user and pass */
	auth_forward(ffd, name, passwd);
	copyloop(0, ffd, timeout);

	_exit(0); /* here all went ok, exit normaly */

}

static char* make_filter(stralloc *value)
/* create a searchfilter, "(uid=VALUE)" */
{
	char *f;
	char *filter;
	
	f = alloc(value->len + 7 ); /* allocate a reagion that is big enough */
	filter = f;
	f += fmt_str(f, "(uid=");
	f += fmt_strn(f, value->s, value->len);
	f += fmt_str(f, ")"); *f++ = 0;

	assert(f-filter <= value->len + 7); /* XXX remove if ok */
	return filter;
}

static void free_filter(char* filter)
{
	alloc_free(filter);
}

