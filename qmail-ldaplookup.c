/* qmail-ldaplookup.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "qmail-ldap.h"
#include "qldap-errno.h"
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

typedef enum mode_d { unset=0, uid, mail} mode_d;

substdio sserr;
substdio ssout;
#define LEN 256
char iobuffer[LEN];
char errbuffer[LEN];

void
usage(void) 
{
	output(&sserr,
	    "usage:\t%s [ -d level ] -u uid [ -p passwd ]\n"
	    "\t%s [ -d level ] -m mail\n", optprogname, optprogname);
	output(&sserr,
	    "\t-d level:\tsets log-level to level\n"
	    "\t-u uid: \tsearch for user id uid (pop3/imap lookup)\n"
	    "\t-p passwd:\tpassword for user id lookups (only by root)\n"
	    "\t-m mail:\tlookup the mailaddress\n");
	_exit(1);
}

int main(int argc, char **argv)
{
	mode_d	mode = unset;
	char	*value = 0;
	char	*passwd = 0;
	int	opt;

	substdio_fdbuf(&ssout, write, STDOUT, iobuffer, sizeof(iobuffer));
	substdio_fdbuf(&sserr, write, STDERR, errbuffer, sizeof(errbuffer));

	while ((opt = getopt(argc, argv, "d:u:m:p:")) != opteof)
		switch (opt) {
		case 'd':
			if (env_put2("LOGLEVEL", optarg) == 0)
				strerr_die2x(1, "ERROR: setting loglevel",
				    error_str(errno));
			break;
		case 'u':
		case 'm':
			if ( mode != unset ) usage();
			mode = opt=='u'?uid:mail;
			value = optarg;
			break;
		case 'p':
			if (mode != uid) usage();
			passwd = optarg;
			break;
		default:
			usage();
		}
	if (argc != optind || mode == unset) usage();

	log_init(STDERR, -1, 0);
	
	strerr_die1x(1, "ERROR: mail lookup not yet available");

	return 0;
}
