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
#include "check.h"
#include "qldap-debug.h"

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

extern stralloc qldap_me;
extern stralloc qldap_objectclass;

int rebind; 
int cluster;

static int check_ldap(stralloc *login,
	   				  stralloc *authdata,
					  unsigned long *uid,
					  unsigned long *gid,
					  stralloc *home,
					  stralloc *maildir);

static int check_passwd(stralloc *login,
	   					stralloc *authdata,
						unsigned long *uid,
						unsigned long *gid,
						stralloc *home,
						stralloc *md);

static int cmp_passwd(unsigned char *clear, char *encrypted);

static int get_local_maildir(stralloc *home, stralloc *maildir);

#ifdef QLDAP_CLUSTER
static void copyloop(int infd, int outfd, int timeout);
static void forward_session(char *host, char *name, char *passwd);
#endif

static int make_filter(stralloc *value, stralloc *filter);
static void free_stralloc(stralloc *sa);

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

	init_debug(STDERR, 255); /* XXX limited to 64 so it is not possible to get
							 * XXX passwords via debug on normal systems */

	auth_init(argc, argv, &login, &authdata);
	debug(256, "auth_init: login=%s, authdata=%s\n", login.s, authdata.s);
	
	if ( init_ldap(&locald, &cluster, &rebind, &homemaker, 0, 0, 0) == -1 ) {
		debug(1, "alert: init_ldap failed.\n");
		_exit(1);
	}
	debug(64, "init_ldap: ld=%i, cluster=%i, rebind=%i, hdm=%s\n", 
			locald, cluster, rebind, homemaker.s);
	
	if ( check_ldap(&login, &authdata, &uid, &gid, &home, &maildir) ) {
		debug(16, "authentication with ldap was not successful\n");
		if ( locald == 1 && 
				(qldap_errno == LDAP_NOSUCH || qldap_errno == LDAP_SEARCH) ) {
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
			   unsigned long *gid, stralloc *home, stralloc *maildir)
{
	userinfo	info;
	extrainfo	extra[2];
	searchinfo	search;
	stralloc    filter = {0};
	int			ret;
	char		*attrs[] = { LDAP_UID, /* the first 6 attrs are default */
							 LDAP_QMAILUID,
							 LDAP_QMAILGID,
							 LDAP_ISACTIVE,
							 LDAP_MAILHOST,
							 LDAP_MAILSTORE,
							 LDAP_HOMEDIR,
							 LDAP_PASSWD, 0 }; /* passwd is extra */

	/* initalize the different info objects */
	if ( rebind ) {
		extra[0].what = 0;	/* under rebind mode no additional info is needed */
		search.bindpw = authdata->s;
		attrs[7] = 0;
		/* rebind on, check passwd via ldap rebind */ 
	} else {
		extra[0].what = LDAP_PASSWD; /* need to get the crypted password */
		search.bindpw = 0; 	/* rebind off */
	}
	extra[1].what = 0;		/* end marker for extra info */
	
	if ( !make_filter(login, &filter ) ) { 
		/* create search filter */
		debug(4, "warning: check_ldap: could not make a filter\n");
		/* qldap_errno set by make_filter */
		return -1;
	}
	search.filter = filter.s;
	
	ret = ldap_lookup(&search, attrs, &info, extra);
	free_stralloc(&filter);	/* free the old filter */
	if ( ret != 0 ) {
		debug(4, "warning: check_ldap: ldap_lookup not successful!\n");
		/* qldap_errno set by ldap_lookup */
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
	if ( info.mms == 0 && info.homedir == 0 ) {
		qldap_errno = AUTH_FAILED;
		return -1; /* user authentification failed no homedir defined */
	}
	if ( info.homedir ) {
		if ( ! stralloc_copys(home, info.homedir) ) {
			qldap_errno = ERRNO;
			return -1;
		}
		if ( info.mms ) {
			if ( ! stralloc_copys(maildir, info.mms) ) {
				qldap_errno = ERRNO;
				return -1;
			}
			/* XXX have a look at check.c and qmail-ldap.h for chck_pathb */
			if ( !chck_pathb(maildir->s,maildir->len) ) {
				debug(2, "warning: check_ldap: path contains illegal chars!\n");
				qldap_errno = ILL_PATH;
				return -1;
			}
		}
		
	} else {
		if ( ! stralloc_copys(home, info.mms) ) {
			qldap_errno = ERRNO;
			return -1;
		}
	}
	/* XXX have a look at check.c and qmail-ldap.h for chck_pathb */
	if ( !chck_pathb(home->s,home->len) ) {
		debug(2, "warning: check_ldap: path contains illegal chars!\n");
		qldap_errno = ILL_PATH;
		return -1;
	}
	if (!stralloc_0(home) ) {
		qldap_errno = ERRNO;
		return -1;
	}
	if (!stralloc_0(maildir) ) {
		qldap_errno = ERRNO;
		return -1;
	}
	/* free a part of the info struct */
	alloc_free(info.user);
	alloc_free(info.uid);
	alloc_free(info.gid);
	if (info.homedir) alloc_free(info.homedir);
	if (info.mms) alloc_free(info.mms);
	
	if ( rebind && search.bind_ok ) {
		debug(32, 
			"check_ldap: ldap_lookup sucessfully authenticated with rebind\n");
		return 0; 
		/* if we got till here under rebind mode, the user is authenticated */
	} else if ( rebind ) {
		debug(32, 
			"check_ldap: ldap_lookup authentication failed with rebind\n");
		qldap_errno = AUTH_FAILED;
		return -1; /* user authentification failed */
	}
	
	if ( ! extra[0].vals ) {
		debug(2, "warning: check_ldap: password is missing for uid %s\n", 
				login);
		qldap_errno = AUTH_NEEDED;
		return -1; 
	}
	
	ret = cmp_passwd((unsigned char*) authdata->s, extra[0].vals[0]); 
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

	/* here we don't check the home and maildir path, if a user has a faked 
	 * passwd entry, then you have a bigger problem on your system than just 
	 * a guy how can read the mail of other users/customers */
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
	ret = cmp_passwd((unsigned char*) authdata->s, spw->sp_pwdp);
#else /* no PW_SHADOW */
#ifdef AIX
	spw = getuserpw(login->s);
	if (!spw) {
		/* XXX: and again */
		qldap_errno = AUTH_ERROR;
		return -1;
	}
	ret = cmp_passwd((unsigned char*) authdata->s, spw->upw_passwd);
#else /* no AIX */
	ret = cmp_passwd((unsigned char*) authdata->s, pw->pw_passwd);
#endif /* END AIX */
#endif /* END PW_SHADOW */
	debug(32, "check_pw: password compare was %s\n", 
			ret==0?"successful":"not successful");
	return ret;
	
}

static int cmp_passwd(unsigned char *clear, char *encrypted)
{
#define HASH_LEN 100	/* XXX is this enough, I think yes */
						/* What do you think ? */
	char hashed[HASH_LEN]; /* these to buffers can not be used for exploits */
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
			MD4DataBase64(clear, str_len(clear), hashed, sizeof(hashed));
		} else if (!str_diffn("{MD5}", encrypted, 5) ) {
			/* MD5 */
			shift = 5;
			MD5DataBase64(clear, str_len(clear), hashed, sizeof(hashed));
		} else if (!str_diffn("{NS-MTA-MD5}", encrypted, 12) ) {
			/* NS-MTA-MD5 */
			shift = 12;
			if (!str_len(encrypted) == 76) {
				qldap_errno = ILL_AUTH;
				return -1;
			} /* boom */
			byte_copy(salt, 32, &encrypted[44]);
			salt[32] = 0;
			ns_mta_hash_alg(hashed, salt, (char *) clear);
			byte_copy(&hashed[32], 33, salt);
		} else if (!str_diffn("{SHA}", encrypted, 5) ) {
			/* SHA */
			shift = 5;
			SHA1DataBase64(clear, str_len(clear), hashed, sizeof(hashed));
		} else  if (!str_diffn("{RMD160}", encrypted, 8) ) {
			/* RMD160 */
			shift = 8;
			RMD160DataBase64(clear, str_len(clear), hashed, sizeof(hashed));
		} else {
			/* unknown hash function detected */ 
			shift = 0;
			qldap_errno = ILL_AUTH;
			return -1;
		}
		/* End getting correct hash-func hashed */
		debug(256, "cpm_passwd: comparing hashed passwd (%s == %s)\n", 
				hashed, encrypted);
		if (!*encrypted || str_diff(hashed,encrypted+shift) ) {
			qldap_errno = AUTH_FAILED;
			return -1;
		}
		/* hashed passwds are equal */
	} else { /* crypt or clear text */
		debug(256, "cpm_passwd: comparing standart passwd (%s == %s)\n", 
				crypt(clear,encrypted), encrypted);
		if (!*encrypted || str_diff(encrypted, crypt(clear,encrypted) ) ) {
			/* CLEARTEXTPASSWD ARE NOT GOOD */
			/* so they are disabled by default */
#ifdef CLEARTEXTPASSWD
#warning ___CLEARTEXT_PASSWORD_SUPPORT_IS_ON___
			if (!*encrypted || str_diff(encrypted, clear) ) {
#endif
			qldap_errno = AUTH_FAILED;
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
	for (match = 0; match<512; buf[match++]=0 ) ; /* trust nobody */
	free_stralloc(&dotqmail);
	return 0;

tryclose:
	for (match = 0; match<512; buf[match++]=0 ) ; /* trust nobody */
	match = errno; /* preserve errno */
	close(fd);
	free_stralloc(&dotqmail);
	errno = match;
	qldap_errno = ERRNO;
	return -1;

}

#ifdef QLDAP_CLUSTER
static void copyloop(int infd, int outfd, int timeout)
{
	fd_set iofds;
	fd_set savedfds;
	int maxfd;			/* Maximum numbered fd used */
	struct timeval tv;
	unsigned long bytes;
	char buf[4096];		/* very big buffer ethernet pkgs are normaly
						   around 1500 bytes long */

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
		/* Set up timeout *//* because of LINUX this has to be done everytime */
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

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
	for(bytes=0; bytes<4096; buf[bytes++] = 0 ) ; /* paranoia */
	return;
}

static void forward_session(char *host, char *name, char *passwd)
{
	ipalloc ip = {0};
	stralloc host_stralloc = {0};
	int ffd;
	int timeout = 31*60; /* ~30 min timeout RFC1730 */
	int ctimeout = 20;
	
	if (!stralloc_copys(&host_stralloc, host)) {
		qldap_errno = ERRNO;
		auth_error();
	}

	dns_init(0);
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

	_exit(0); /* all went ok, exit normaly */

}
#endif /* QLDAP_CLUSTER */

static int make_filter(stralloc *value, stralloc *filter)
/* create a searchfilter, "(uid=VALUE)" */
{
	stralloc tmp = {0};
	
	
	if ( !stralloc_copy(&tmp, value) ) {
		qldap_errno = ERRNO;
		return 0;
	}
	if ( !escape_forldap(&tmp) ) {
		qldap_errno = ERRNO;
		return 0;
	}
	if ( !stralloc_copys(filter, "(") ||
		 !stralloc_cats(filter, LDAP_UID) ||
		 !stralloc_cats(filter, "=") ||
		 !stralloc_cat(filter, &tmp) ||
		 !stralloc_cats(filter, ")") || 
		 !stralloc_0(filter) ) {
		qldap_errno = ERRNO;
		return 0;
	}
	free_stralloc(&tmp);
	return 1;
}

static void free_stralloc(stralloc* sa)
{
	alloc_free(sa->s);
	sa->s = 0;
	return;
}

