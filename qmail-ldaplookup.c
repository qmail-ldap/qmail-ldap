/* qmail-ldaplookup.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "qmail-ldap.h"
#include "qldap-errno.h"
#include "qldap-ldaplib.h"
#include "stralloc.h"
#include "alloc.h"
#include "error.h"
#include "strerr.h"
#include "str.h"
#include "output.h"
#include "qldap-debug.h"
#include "check.h"
#include "substdio.h"
#include "fmt.h"
#include "scan.h"
#include "readwrite.h"
#include "byte.h"
#include "getln.h"
#include <sys/types.h>
#include "digest_md4.h"
#include "digest_md5.h"
#include "digest_rmd160.h"
#include "digest_sha1.h"
#include "open.h"
#include "sgetopt.h"
#include "env.h"
#include "auto_break.h"
#include "constmap.h"

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

typedef enum mode_d { unset=0, uid, mail} mode_d;

extern stralloc qldap_me;
extern stralloc qldap_objectclass;

#ifdef QLDAP_CLUSTER
extern struct constmap qldap_mailhosts;
#endif

int rebind; 
int cluster;
int locald;

stralloc homemaker = {0};
stralloc defdot = {0};
stralloc defquota = {0};
stralloc quotawarning = {0};
stralloc filter = {0};
stralloc value = {0};
stralloc home = {0};
stralloc md = {0};

substdio ssout;
#define LEN 256
char buffer[LEN];

static int cmp_passwd(unsigned char *clear, char *encrypted);
static void local_lookup(char *username, char *passwd);
int create_mail_filter();
int create_uid_filter();

void usage() 
{
	output(&ssout, "usage: qmail-ldaplookup [-d level] {-u uid [-p passwd] | -m mail}\n", optprogname);
	output(&ssout, "\t-d level:\tsets log-level to level\n\
\t-u uid: \tsearch for user id uid (pop3/imap lookup)\n\
\t-p passwd:\tpassword for user id lookups (XXX only root)\n\
\t-m mail:\tlookup the mailaddress\n");
			_exit(1);
}

int main(int argc, char **argv)
{
	mode_d mode = unset;
	userinfo	info;
	extrainfo	extra[13];
	searchinfo	search;
	int			ret, i, j;
	unsigned long tid;
	char		*attrs[] = { 
					LDAP_UID, /* the first 7 attrs are default */
					LDAP_QMAILUID,
					LDAP_QMAILGID,
					LDAP_ISACTIVE,
					LDAP_MAILHOST,
					LDAP_MAILSTORE,
					LDAP_HOMEDIR,
					LDAP_QUOTA_SIZE,  /* the last 8 are aditional infos */
					LDAP_QUOTA_COUNT,
					LDAP_QUOTA,
					LDAP_MAIL,
					LDAP_MAILALTERNATE,
					LDAP_FORWARDS,
					LDAP_PROGRAM,
					LDAP_MODE,
					LDAP_REPLYTEXT,
					LDAP_DOTMODE,
					LDAP_MAXMSIZE,
					LDAP_PASSWD, 0 }; /* passwd is extra */
	char* passwd = 0;
	int opt;
	int done;


	substdio_fdbuf(&ssout, write, STDOUT, buffer, sizeof(buffer) );

	while ( ( opt = getopt(argc, argv, "d:u:m:p:") ) != opteof)
		switch (opt) {
			case 'd':
				if ( env_put2("LOGLEVEL", optarg) == 0 )
					strerr_die2x(1, "ERROR: setting loglevel", error_str(errno));
				break;
			case 'u':
			case 'm':
				if ( mode != unset ) usage();
				mode = opt=='u'?uid:mail;
				if ( ! stralloc_copys(&value, optarg) ) {
					strerr_die2x(1, "ERROR: ", error_str(errno));
				}
				break;
			case 'p':
				if ( mode != uid ) usage();
				passwd = optarg;
				break;
			default:
				usage();
		}
	if ( argc != optind || mode == unset ) usage();

	log_init(STDERR, -1, 0);

	if ( init_ldap( &locald, &cluster, &rebind, &homemaker, &defdot, &defquota,
				&quotawarning) == -1 ) {
		strerr_die2x(1, "ERROR: init_ldap failed: ", qldap_err_str(qldap_errno));
	}

	output(&ssout, "init_ldap:\tpasswords are %scompared via rebind\n",
			rebind?"":"not ");
	output(&ssout, "\t\tlocaldelivery:\t %s\n\t\tclustering:\t %s\n",
			locald?"on":"off", cluster?"on":"off");
	output(&ssout, "\t\tldapobjectclass: %S\n", &qldap_objectclass);
	output(&ssout, "\t\thomedirmaker:\t %s\n", homemaker.len?homemaker.s:"undefined");
	output(&ssout, "\t\tdefaultDotMode:\t %s\n", defdot.s);
	output(&ssout, "\t\tdefaultQuota:\t %s\n", defquota.len?defquota.s:"undedined");
	output(&ssout, "\t\tQuotaWarning:\n------\n%s\n------\n", 
			quotawarning.len?quotawarning.s:"undefined");

	/* initalize the different objects */
	extra[12].what = 0; /* end marker for extra info */
	extra[0].what = LDAP_MAIL;
	extra[1].what = LDAP_MAILALTERNATE;
	extra[2].what = LDAP_QUOTA_SIZE;
	extra[3].what = LDAP_QUOTA_COUNT;
	extra[4].what = LDAP_QUOTA;
	extra[5].what = LDAP_FORWARDS;
	extra[6].what = LDAP_PROGRAM;
	extra[7].what = LDAP_DOTMODE;
	extra[8].what = LDAP_MODE;
	extra[9].what = LDAP_REPLYTEXT;
	extra[10].what= LDAP_MAXMSIZE;
	if ( mode == mail ) {
		extra[11].what = 0; /* under mail lookups no passwords are compared */
		attrs[18] = 0;
		search.bindpw = 0; /* rebind off */
	} else if (!passwd || rebind ) {
		extra[11].what = 0; /* passwd lookup not needed */
		attrs[18] = 0;
		search.bindpw = 0; /* rebind off */
		if (rebind) {
			search.bindpw = argv[3];
		}
	} else {
		extra[11].what = LDAP_PASSWD; /* need to get the crypted password */
		search.bindpw = 0; 	/* rebind off */
	}
	if ( !escape_forldap(&value) ) {
		strerr_die2x(1, "ERROR: escape_forldap failed: ", error_str(errno) );
	}

	ret = qldap_open();
	if ( ret != 0 ) 
		strerr_die2x(1, "qldap_open:\tNOT successful: ", 
				qldap_err_str(qldap_errno));

	do {
		if ( mode == mail )
			done = create_mail_filter();
		else
			done = create_uid_filter();
		
		search.filter = filter.s;
		output(&ssout, "qldap_lookup:\tsearching with %s\n", filter.s);
		ret = qldap_lookup(&search, attrs, &info, extra);
		if ( ret != 0 ) {
			output(&ssout, "qldap_lookup:\tNOT successful: %s\n", 
					qldap_err_str(qldap_errno));
		} else {
			output(&ssout, "qldap_lookup:\tsucceeded, found:\n");
			break;
		}
	} while ( !done ) ;
	qldap_close(); /* now close the ldap (TCP) connection */


	if ( ret != 0 ) {
		if ( mode == uid && locald ) {
			output(&ssout, "Will try a local password lookup\n");
			if ( !stralloc_0(&value) ) {
				strerr_die2x(1, "ERROR: ",
						error_str(errno));
			}
			local_lookup(value.s, passwd);
		} else {
			output(&ssout, "%s\n", mode!=uid?"user not found giving up":
					"localdelivery off, so no local lookup");
			exit(111);
		}
	}

	output(&ssout, "\t\t%s: %s\n", LDAP_UID, info.user);
	if (!chck_users(info.user) ) {
		output(&ssout, "\tWARNING %s contains illegal chars!\n", LDAP_UID);
	}
	output(&ssout, "\t\t%s: %s\n\t\t%s: %s\n",
			LDAP_QMAILUID, info.uid, LDAP_QMAILGID, info.gid);
	scan_ulong(info.uid, &tid);
	if (UID_MIN > tid || tid > UID_MAX ) {
		output(&ssout, "\tWARNING %s is out of range (%i...%i)\n", 
				LDAP_QMAILUID, UID_MIN, UID_MAX);
	}
	scan_ulong(info.gid, &tid);
	if (GID_MIN > tid || tid > GID_MAX ) {
		output(&ssout, "\tWARNING %s is out of range (%i...%i)\n", 
				LDAP_QMAILGID, GID_MIN, GID_MAX);
	}
	output(&ssout, "\t\t%s: %s\n", LDAP_ISACTIVE, 
			info.status==STATUS_BOUNCE?ISACTIVE_BOUNCE:
			info.status==STATUS_BOUNCE?ISACTIVE_DELETE:
			info.status==STATUS_NOPOP?ISACTIVE_NOPOP:
			info.status==STATUS_OK?ISACTIVE_ACTIVE:"undefined");

	output(&ssout, "\t\t%s: %s\n", LDAP_MAILSTORE, info.mms);
	if (info.mms) if ( !chck_paths(info.mms) ) {
		output(&ssout, "\tWARNING %s contains illegal chars!\n", LDAP_MAILSTORE);
	}
	output(&ssout, "\t\t%s: %s\n", LDAP_HOMEDIR, info.homedir);
	if (info.homedir) if ( !chck_paths(info.homedir) ) {
		output(&ssout, "\tWARNING %s contains illegal chars!\n", LDAP_HOMEDIR);
	}

	output(&ssout, "\t\t%s: %s\n", LDAP_MAILHOST, info.host);
	if ( cluster && info.host &&
		 str_diff(qldap_me.s, info.host) 
#ifdef QLDAP_CLUSTER 
		 /* qldap_mailhosts only defined when QLDAP_CLUSTER defined */
		 && !constmap(&qldap_mailhosts, info.host, str_len(info.host)) 
#endif
		 ) {
		/* hostname is different, so I would reconnect */
		output(&ssout, "\tINFO    would reconnect to host %s\n", info.host);
	}

	/* free a part of the info struct */
	alloc_free(info.user);
	alloc_free(info.uid);
	alloc_free(info.gid);
	if (info.mms) alloc_free(info.mms);
	if (info.homedir) alloc_free(info.homedir);
	alloc_free(info.host);

	for ( i = 0; extra[i].what != 0; i++ ) {
		if ( extra[i].vals != 0 ) {
			output(&ssout, "\t\t%s: %s\n", extra[i].what, extra[i].vals[0]);
			for ( j = 1; extra[i].vals[j] != 0; j++ ) {
				output(&ssout, "\t\t\t\t %s\n", extra[i].vals[j]);
				if ( i == 4 && !chck_progs(extra[i].vals[j]) ) { 
					output(&ssout, "\tWARNING %s contains illegal chars!\n", 
							LDAP_PROGRAM);
				}
			}
		} else {
			output(&ssout, "\t\t%s: no entry in the database\n", extra[i].what);
		}
	}

	if ( mode == uid && passwd && !rebind && 
			extra[11].vals && extra[11].vals[0] ) {
		ret = cmp_passwd((unsigned char *) passwd, extra[11].vals[0] );
		output(&ssout, "qldap_lookup:\tpassword compare was %s\n", 
				ret==0?"successful":"not successful");
	}
	/* now it's save to free the entries, thanks to Sascha Gresk for the indication */
	for ( i = 0; extra[i].what != 0; i++ )
		ldap_value_free(extra[i].vals);

	return 0;
}

int create_mail_filter()
{
	static int at = 0;
	static int i = 0;
	char* s = value.s;
	int len = value.len;

	if ( at == 0 ) { /* first round */
		for (at = len - 1; s[at] != '@' && at >= 0 ; at--) ; 
		/* handels also mail with 2 @ */
		/* at = index to last @ sign in mail address */
		/* s = mailaddress, len = lenght of address */
		/* i = position of current '-' */
		if ( at == -1 ) {
			strerr_die1x(1, "ERROR: invalid mailaddress: no '@' present"); 
		}	
		i = at;
	}

	/* this handles the "catch all" and "-default" extension */
	/* but also the normal eMail address */

	/* build the search string for the email address */
	if (!stralloc_copys(&filter,"(" ) ) goto nomem;
	/* optional objectclass */
	if ( qldap_objectclass.len ) { 
		if (!stralloc_cats(&filter,"&(")) goto nomem;
		if (!stralloc_cats(&filter,LDAP_OBJECTCLASS)) goto nomem;
		if (!stralloc_cats(&filter,"=")) goto nomem;
		if (!stralloc_cat(&filter,&qldap_objectclass)) goto nomem;
		if (!stralloc_cats(&filter,")(")) goto nomem;
	} /* end */

	/* mail address */
	if (!stralloc_cats(&filter,"|(")) goto nomem;
	if (!stralloc_cats(&filter,LDAP_MAIL)) goto nomem;
	if (!stralloc_cats(&filter,"=")) goto nomem;
	/* username till current '-' */
	if (!stralloc_catb(&filter,s, i)) goto nomem;
	if ( i != at ) { /* do not append catchall in the first round */
		/* catchall or default */
		if ( i != 0 ) /* add '-' */
			if (!stralloc_cats(&filter,auto_break)) goto nomem;
		if (!stralloc_cats(&filter,LDAP_CATCH_ALL)) goto nomem;
	}
	/* @damin.com */
	if (!stralloc_catb(&filter,s+at, len-at)) goto nomem;

	/* mailalternate address */
	if (!stralloc_cats(&filter,")(")) goto nomem;
	if (!stralloc_cats(&filter,LDAP_MAILALTERNATE)) goto nomem;
	if (!stralloc_cats(&filter,"=")) goto nomem;
	/* username till current '-' */
	if (!stralloc_catb(&filter,s, i)) goto nomem;
	if ( i != at ) { /* do not append catchall in the first round */
		/* catchall or default */
		if ( i != 0 ) /* add '-' */
			if (!stralloc_cats(&filter,auto_break)) goto nomem;
	if (!stralloc_cats(&filter,LDAP_CATCH_ALL)) goto nomem;
	}
	/* @damin.com */
	if (!stralloc_catb(&filter,s+at, len-at)) goto nomem;
	if (!stralloc_cats(&filter,"))")) goto nomem;

	/* optional objectclass */
	if ( qldap_objectclass.len ) { 
		if (!stralloc_cats(&filter,")")) goto nomem;
	} /* end */
	if (!stralloc_0(&filter)) goto nomem;

	if ( i == 0 ) return 1;

	/* this is for the next turn */
#ifdef DASH_EXT
	/* XXX if mail starts with a - it will probably not work as expected */
	while ( i != 0 ) {
		i--;
		if ( s[i] == *auto_break ) break;
	}
#else
	/* normal qmial-ldap behavior test for username@domain.com and
	   catchall@domain.com */
	i = 0;
#endif
	return 0;

nomem:
	strerr_die2x(1, "ERROR: can not create a filter: ",
			error_str(errno));
	return 1; /* to make gcc happy */
}

int create_uid_filter()
{
	if ( !stralloc_copys(&filter,"(") ) {
		strerr_die2x(1, "ERROR: can not create a filter: ",
				error_str(errno));
	}		
	if ( qldap_objectclass.len && (
		!stralloc_cats(&filter,"&(" ) || 
		!stralloc_cats(&filter,LDAP_OBJECTCLASS) ||
		!stralloc_cats(&filter,"=") ||
		!stralloc_cat(&filter,&qldap_objectclass) ||
		!stralloc_cats(&filter,")(") ) ) {
		strerr_die2x(1, "ERROR: can not create a filter: ",
				error_str(errno));
	}
	if ( !stralloc_cats(&filter, LDAP_UID) ||
		!stralloc_cats(&filter, "=") ||
		!stralloc_cat(&filter, &value) ||
		!stralloc_cats(&filter, ")") ) {
		strerr_die2x(1, "ERROR: can not create a filter: ", 
				error_str(errno));
	}
	if ( qldap_objectclass.len &&
		!stralloc_cats(&filter,")") ) {
		strerr_die2x(1, "ERROR: can not create a filter: ",
				error_str(errno));
	}
	if ( !stralloc_0(&filter) ) {
		strerr_die2x(1, "ERROR: can not create a filter: ",
				error_str(errno));
	}
	return 1;
}

static int get_local_maildir(stralloc *home, stralloc *maildir);

static void local_lookup(char *username, char *passwd)
{
	int ret;
	struct passwd *pw;
#ifdef PW_SHADOW
	struct spwd *spw;
#endif
#ifdef AIX
	struct userpw *spw;
#endif

	pw = getpwnam(username);
	if (!pw) {
		/* XXX: unfortunately getpwnam() hides temporary errors */
		output(&ssout, "local_lookup:\tuser %s not found in passwd db\n", username);
		_exit(0);
	}
	output(&ssout, "local_lookup:\tsucceeded\n\t\tuser %s found in passwd database\n", 
			username);
	output(&ssout, "\t\tuid: %u\n\t\tgid: %u\n",
			pw->pw_uid, pw->pw_gid);
	if (UID_MIN > pw->pw_uid || pw->pw_uid > UID_MAX ) {
		output(&ssout, "\tWARNING uid is out of range (%i...%i)\n", 
				UID_MIN, UID_MAX);
	}
	if (GID_MIN > pw->pw_gid || pw->pw_gid > GID_MAX ) {
		output(&ssout, "\tWARNING gid is out of range (%i...%i)\n", 
				GID_MIN, GID_MAX);
	}

	/* here we don't check the home and maildir path, if a user has a faked 
	 * passwd entry, then you have a bigger problem on your system than just 
	 * a guy how can read the mail of other users/customers */
	output(&ssout, "\t\thome: %s\n", pw->pw_dir );
	if (!stralloc_copys(&home, pw->pw_dir) ) {
		strerr_die2x(1, "ERROR: local_lookup: ", 
				error_str(errno));
	}

	if ( get_local_maildir(&home, &md) == -1 ) {
		strerr_die2x(1, "ERROR: local_lookup: ", 
				qldap_err_str(qldap_errno));
	}
	output(&ssout, "\t\tmaildir: %s (from ~/.qmail)\n", md.s);

	if ( !passwd ) {
		output(&ssout, "No more information available\n");
		_exit(0);
	}
#ifdef PW_SHADOW
	spw = getspnam(username);
	if (!spw) {
		/* XXX: again, temp hidden */
		qldap_errno = AUTH_ERROR;
		strerr_die2x(1, "ERROR: local_lookup: ", 
				qldap_err_str(qldap_errno));
	}
	output(&ssout, "\t\tcrypted passwd: %s\n", spw->sp_pwdp);
	ret = cmp_passwd((unsigned char *) passwd, spw->sp_pwdp);
#else /* no PW_SHADOW */
#ifdef AIX
	spw = getuserpw(username);
	if (!spw) {
		/* XXX: and again */
		qldap_errno = AUTH_ERROR;
		strerr_die2x(1, "ERROR: local_lookup: ", 
				qldap_err_str(qldap_errno));
	}
	output(&ssout, "\t\tcrypted passwd: %s\n", spw->upw_passwd);
	ret = cmp_passwd((unsigned char *) passwd, spw->upw_passwd);
#else /* no AIX */
	output(&ssout, "\t\tcrypted passwd: %s\n", pw->pw_passwd);
	ret = cmp_passwd((unsigned char *) passwd, pw->pw_passwd);
#endif /* END AIX */
#endif /* END PW_SHADOW */
	output(&ssout, "local_lookup:\tpassword compare was %s\n", 
			ret==0?"successful":"not successful");
	_exit(0);
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
			if ( ns_mta_hash_alg(hashed, salt, (char *) clear) == -1 ) {
				qldap_errno = ERRNO;
				return -1;
			}
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
		log(256, "cpm_passwd: comparing hashed passwd (%s == %s)\n", 
				hashed, encrypted+shift);
		if (!*encrypted || str_diff(hashed,encrypted+shift) ) {
			qldap_errno = AUTH_FAILED;
			return -1;
		}
		/* hashed passwds are equal */
	} else { /* crypt or clear text */
		log(256, "cpm_passwd: comparing standart passwd (%s == %s)\n", 
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
	return 0;

tryclose:
	for (match = 0; match<512; buf[match++]=0 ) ; /* trust nobody */
	match = errno; /* preserve errno */
	close(fd);
	errno = match;
	qldap_errno = ERRNO;
	return -1;

}

