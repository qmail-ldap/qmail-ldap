/* qmail-ldaplookup.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "qmail-ldap.h"
#include "qldap-errno.h"
#include "qldap-ldaplib.h"
#include "stralloc.h"
#include "alloc.h"
#include "error.h"
#include "strerr.h"
#include "str.h"
#include "qldap-debug.h"
#include "check.h"
#include "substdio.h"
#include "fmt.h"
#include "scan.h"
#include "readwrite.h"
#include "byte.h"
#include "getln.h"
#include <sys/types.h>
#include "compatibility.h"
#include "digest_md4.h"
#include "digest_md5.h"
#include "digest_rmd160.h"
#include "digest_sha1.h"
#include "open.h"

#include <stdarg.h>

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

typedef enum mode_d { uid, mail} mode_d;

extern stralloc qldap_me;

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
#define LEN 1024
char buffer[LEN];

void output(char *fmt, ...);
static int cmp_passwd(char *clear, char *encrypted);
static void local_lookup(char *username, char *passwd);

void usage() 
{
	output( "qmail-ldaplookup: usage qmail-ldaplookup {-u uid | -m mail}\n");
	_exit(1);
}

int main(int argc, char **argv)
{
	mode_d mode;
	userinfo	info;
	extrainfo	extra[10];
	searchinfo	search;
	int			ret, i, j;
	unsigned long tid;
	char		*attrs[] = { LDAP_UID, /* the first 6 attrs are default */
							 LDAP_QMAILUID,
							 LDAP_QMAILGID,
							 LDAP_ISACTIVE,
							 LDAP_MAILHOST,
							 LDAP_MAILSTORE,
							 LDAP_QUOTA, /* the last 6 are extra infos */
							 LDAP_MAIL,
							 LDAP_MAILALTERNATE,
							 LDAP_FORWARDS,
							 LDAP_PROGRAM,
							 LDAP_MODE,
							 LDAP_REPLYTEXT,
							 LDAP_DOTMODE,
							 LDAP_PASSWD, 0 }; /* passwd is extra */

	
	init_debug(STDERR, -1);
	substdio_fdbuf(&ssout, write, STDOUT, buffer, sizeof(buffer) );
	
	if (!argv[1] || !argv[2]) {
		usage();
	}
	
	if ( ! stralloc_copys(&value, argv[2]) ) {
		strerr_die2x(1, "ERROR: ", error_str(errno));
	}
	if (!str_diff(argv[1], "-u") ) {
		mode = uid;
	} else if (!str_diff(argv[1], "-m") ) {
		mode = mail;
	} else usage();
	
	if ( init_ldap( &locald, &cluster, &rebind, &homemaker, &defdot, &defquota,
					&quotawarning) == -1 ) {
		strerr_die2x(1, "ERROR: init_ldap faild: ", qldap_err_str(qldap_errno));
	}
	
	output( "init_ldap:\tlocaldelivery:\t%s\n\t\tclustering:\t%s\n",
			locald?"on":"off", cluster?"on":"off");
	output( "\t\thomedirmaker:\t%s\n", homemaker.s);
	output( "\t\tpasswords are %scompared via rebind\n",rebind?"":"not ");

	/* initalize the different objects */
	extra[9].what = 0; /* end marker for extra info */
	extra[2].what = LDAP_QUOTA;
	extra[3].what = LDAP_FORWARDS;
	extra[4].what = LDAP_PROGRAM;
	extra[6].what = LDAP_MODE;
	extra[7].what = LDAP_REPLYTEXT;
	extra[5].what = LDAP_DOTMODE;
	extra[0].what = LDAP_MAIL;
	extra[1].what = LDAP_MAILALTERNATE;
	if ( mode == mail ) {
		extra[8].what = 0; /* under mail lookups no passwords are compared */
		attrs[14] = 0;
		search.bindpw = 0; /* rebind off */
	} else if (!argv[3] || rebind ) {
		extra[8].what = 0; /* passwd lookup not needed */
		attrs[14] = 0;
		search.bindpw = 0; /* rebind off */
		if (rebind) {
			search.bindpw = argv[3];
		}
	} else {
		extra[8].what = LDAP_PASSWD; /* need to get the crypted password */
		search.bindpw = 0; 	/* rebind off */
	}
	if ( !escape_forldap(&value) ) {
		strerr_die2x(1, "ERROR: escape_forldap faild: ", error_str(errno) );
	}
	if ( mode == mail) {
		/* build the search string for the email address */
		if ( !stralloc_copys(&filter,"(|(mail=" ) ||
			 !stralloc_cat(&filter,&value) ||
			 !stralloc_cats(&filter,")(mailalternateaddress=") ||
			 !stralloc_cat(&filter,&value) ||
			 !stralloc_cats(&filter,"))") ||
			 !stralloc_0(&filter)) {
			strerr_die2x(1, "ERROR: can not create a filter: ", 
					error_str(errno));
		}
	} else {
		if ( !stralloc_copys(&filter, "(") ||
			 !stralloc_cats(&filter, LDAP_UID) ||
			 !stralloc_cats(&filter, "=") ||
			 !stralloc_cat(&filter, &value) ||
			 !stralloc_cats(&filter, ")") || 
			 !stralloc_0(&filter) ) {
			strerr_die2x(1, "ERROR: can not create a filter: ", 
					error_str(errno));
		}
	}
	search.filter = filter.s;
	output( "ldap_lookup:\tsearching with %s\n", filter.s);
	ret = ldap_lookup(&search, attrs, &info, extra);
	if ( ret != 0 ) {
		output("ERROR: ldap_lookup not successful: ", 
				qldap_err_str(qldap_errno));
		if ( mode == uid && locald ) {
			output("Will try a local password lookup\n");
			local_lookup(argv[2], argv[3]);
		} else {
			output("%s\n", mode==uid?"only uid lookups can be local":
									"localdelivery of so no local lookup");
			exit(111);
		}
	}
	output( "ldap_lookup:\tsucceded, found:\n");
	output( "\t\t%s: %s\n", LDAP_UID, info.user);
	if (!chck_users(info.user) ) {
		output( "\tWARNING %s contains illegal chars!\n", LDAP_UID);
	}
	output( "\t\t%s: %s\n\t\t%s: %s\n",
			LDAP_QMAILUID, info.uid, LDAP_QMAILGID, info.gid);
	scan_ulong(info.uid, &tid);
	if (UID_MIN > tid || tid > UID_MAX ) {
		output( "\tWARNING %s is out of range (%i...%i)\n", 
				LDAP_QMAILUID, UID_MIN, UID_MAX);
	}
	scan_ulong(info.gid, &tid);
	if (GID_MIN > tid || tid > GID_MAX ) {
		output( "\tWARNING %s is out of range (%i...%i)\n", 
				LDAP_QMAILGID, GID_MIN, GID_MAX);
	}
	output( "\t\t%s: %s\n", LDAP_ISACTIVE, 
			info.status==STATUS_BOUNCE?ISACTIVE_BOUNCE:
			info.status==STATUS_NOPOP?ISACTIVE_NOPOP:
			info.status==STATUS_OK?ISACTIVE_ACTIVE:"undefined");
	output( "\t\t%s: %s\n", LDAP_MAILSTORE, info.mms);
	if ( !chck_paths(info.mms) ) {
		output( "\tWARNING %s contains illegal chars!\n", LDAP_MAILSTORE);
	}
	output( "\t\t%s: %s\n", LDAP_MAILHOST, info.host);
	if ( cluster && info.host && str_diff(qldap_me.s, info.host) ) {
		/* hostname is different, so I would reconnect */
		output( "\tINFO    would reconnect to host %s\n", info.host);
	}

	/* free a part of the info struct */
	alloc_free(info.user);
	alloc_free(info.uid);
	alloc_free(info.gid);
	alloc_free(info.mms);
	alloc_free(info.host);
	
	for ( i = 0; extra[i].what != 0; i++ ) {
		if ( extra[i].vals != 0 ) {
			output( "\t\t%s: %s\n", extra[i].what, extra[i].vals[0]);
			for ( j = 1; extra[i].vals[j] != 0; j++ ) {
				output( "\t\t\t\t %s\n", extra[i].vals[j]);
			}
			ldap_value_free(extra[i].vals);
		} else {
			output( "\t\t%s: no entry in the database\n", extra[i].what);
		}
	}
	
	if ( mode == uid && argv[3] && !rebind ) {
		ret = cmp_passwd(argv[3], extra[8].vals[0] );
		output( "ldap_lookup:\tpassword compare was %s\n", 
				ret==0?"successful":"not successful");
	}
	return 0;
}

char num[FMT_ULONG];
static const char nullString[] = "(null pointer)";

void output(char *fmt, ...)
/* works like printf has the format options %i, ...
 * all flags (#, 0, -, ' ', +, ' ... ) are not supported if not special noted
 * Also not supported are all options for foating-point numbers 
 * (not needed in qmail)
 * Supported conversion specifiers: diouxcsSp%
 * diux are for integer (long) conversions
 * c is a single unsigned char
 * s is a zero terminated string
 * S is a stralloc object (should not be zero terminated (else the zero 
 *   will be printed))
 * % is the % sign */
{
	va_list args;
	unsigned long ul;
	long l;
	char *s;
	char *start;
	char *cur;
	unsigned char c;
	stralloc *sa;
	va_start(args,fmt);

	start = fmt;
	cur = fmt;
	while (*cur) {
		if (*cur == '%') {
			if ( substdio_put(&ssout, start, cur-start) == -1 ) return;
			cur++;
			switch (*cur) {
				case 'd':
				case 'i':
					l = va_arg(args, long);
					if ( l < 0 ) { /* negativ number, d and i are signed */
						l *= -1;
						if ( substdio_put(&ssout, "-", 1) == -1 ) return;
					}
					ul = (unsigned long) l;
					if ( substdio_put(&ssout, num, fmt_ulong(num, ul) ) ) 
						return;
					break;
				case 'u':
					ul = va_arg(args, unsigned long);
					if ( substdio_put(&ssout, num, fmt_ulong(num, ul) ) ) 
						return;
					break;
				case 's':
					s = va_arg(args, char *);
					if ( !s ) {
						 if ( substdio_put(&ssout, nullString, 
									 		str_len(nullString) ) ) 
							 return;
						 break;
					}
					if ( substdio_put(&ssout, s, str_len(s) ) ) return;
					break;
				case 'S':
					sa = va_arg(args, stralloc *);
					if ( !sa ) {
						if ( substdio_put(&ssout, nullString, 
											str_len(nullString) ) )
							return;
						break;
					}
					if ( substdio_put(&ssout, sa->s, sa->len ) ) return;
					break;
				case '%':
					if ( substdio_put(&ssout, "%", 1) == -1 ) return;
					break;
				case 'c':
					c = va_arg(args, unsigned char);
					substdio_BPUTC(&ssout, c);
					break;
			}
			start = ++cur; 
		} else {
			++cur;
		}
	}
	if ( substdio_put(&ssout, start, cur-start) == -1 ) return;
	if ( substdio_flush(&ssout) == -1 ) return;
	va_end(args);
	
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
		output("local_lookup:\tuser %s not found in passwd db\n", username);
		_exit(0);
	}
	output( "local_lookup:\tsucceded\n\t\tuser %s found in passwd database\n", 
			username);
	output( "\t\tuid: %u\n\t\tgid: %u\n",
			pw->pw_uid, pw->pw_gid);
	if (UID_MIN > pw->pw_uid || pw->pw_uid > UID_MAX ) {
		output( "\tWARNING uid is out of range (%i...%i)\n", 
				UID_MIN, UID_MAX);
	}
	if (GID_MIN > pw->pw_gid || pw->pw_gid > GID_MAX ) {
		output( "\tWARNING gid is out of range (%i...%i)\n", 
				GID_MIN, GID_MAX);
	}

	/* here we don't check the home and maildir path, if a user has a faked 
	 * passwd entry, then you have a bigger problem on your system than just 
	 * a guy how can read the mail of other users/customers */
	output( "\t\thome: %s\n", pw->pw_dir );
	if (!stralloc_copys(&home, pw->pw_dir) ) {
		strerr_die2x(1, "ERROR: local_lookup: ", 
				error_str(errno));
	}
	
	if ( get_local_maildir(&home, &md) == -1 ) {
		strerr_die2x(1, "ERROR: local_lookup: ", 
				qldap_err_str(qldap_errno));
	}
	output( "\t\tmaildir: %s (from ~/.qmail)\n", md.s);
	
	if ( !passwd ) {
		output( "No more information available\n");
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
	output( "\t\tcrypted passwd: %s\n", spw->sp_pwdp);
	ret = cmp_passwd(passwd, spw->sp_pwdp);
#else /* no PW_SHADOW */
#ifdef AIX
	spw = getuserpw(username);
	if (!spw) {
		/* XXX: and again */
		qldap_errno = AUTH_ERROR;
		strerr_die2x(1, "ERROR: local_lookup: ", 
				qldap_err_str(qldap_errno));
	}
	output( "\t\tcrypted passwd: %s\n", spw->upw_passwd);
	ret = cmp_passwd(passwd, spw->upw_passwd);
#else /* no AIX */
	output( "\t\tcrypted passwd: %s\n", pw->pw_passwd);
	ret = cmp_passwd(passwd, pw->pw_passwd);
#endif /* END AIX */
#endif /* END PW_SHADOW */
	output( "local_lookup:\tpassword compare was %s\n", 
			ret==0?"successful":"not successful");
	_exit(0);
}

static int cmp_passwd(char *clear, char *encrypted)
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
			ns_mta_hash_alg(hashed, salt, clear);
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
				hashed, encrypted+shift);
		if (!*encrypted || str_diff(hashed,encrypted+shift) ) {
			qldap_errno = AUTH_FAILD;
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

