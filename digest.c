#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "base64.h"
#include "error.h"
#include "passwd.h"
#include "qldap-errno.h"
#include "readwrite.h"
#include "sgetopt.h"
#include "stralloc.h"


#define RANDDEV "/dev/urandom"

const char *mode[] = {
	"{CRYPT}",
       	"{MD4}",
       	"{MD5}",
       	"{NS-MTA-MD5}",
       	"{SMD5}",
       	"{SHA}",
       	"{SSHA}",
       	"{RMD160}",
       	0 };

stralloc pw = {0};
stralloc salt = {0};

void
usage(void)
{
	fprintf(stderr,
	    "usage:\tdigest [ -c ] [ -b | -5 | -C | -f cryptformat ] [ -s base64Salt ]\n\t[ -S hexSalt ] passwd\n"
	    "\tdigest -v password hashedPassword\n");
	exit(1);
}

void
getsalt(stralloc *b, int blen)
{
	char buf[64];
	int l, fd;
	
	fd = open(RANDDEV, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "digest: open %s failed: %s.\n",
		    RANDDEV, error_str(errno));
		exit(1);
	}
	l = read(fd, buf, sizeof(buf));
	if (l == -1) {
		fprintf(stderr, "digest: read failed: %s.\n",
		    error_str(errno));
		exit(1);
	}
	if (l < blen) {
		fprintf(stderr, "digest: not enough random data read.\n");
		exit(1);
	}
	if (!stralloc_copyb(b, buf, blen)) {
		fprintf(stderr, "digest: stralloc_copyb failed: %s.\n",
		    error_str(errno));
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int	i, opt, m;
	char	*clear, *encrypted;
	const char *cformat;
	
	clear = (char *)0;
	encrypted = (char *)0;
	m = 0;
	cformat = "XX";
	while ((opt = getopt(argc, argv, "5bcf:s:S:v")) != opteof)
		switch (opt) {
		case '5':
			/* md5 format */
			cformat = "$1$XXXXXXXX$";
			break;
		case 'b':
			/* blowfish format */
			cformat = "$2a$07$XXXXXXXXXXXXXXXXXXXXXXXX";
			break;
		case 'C':
			/* good (acctually bad) old crypt */
			cformat = "XX";
			break;
		case 'c':
			m = 0;
			break;
		case 'f':
			cformat = optarg;
			break;
		case 's':
			if (b64_ptons(optarg, &salt) == -1) {
				fprintf(stderr, "digest: bad base64 string.\n");
				usage();
			}
			break;
		case 'S':
			if (hex_ptons(optarg, &salt) == -1) {
				fprintf(stderr, "digest: bad hex string.\n");
				usage();
			}
			break;
		case 'v':
			m = 1;
			break;
		default:
			
			usage();
		}

	argc -= optind;
	argv += optind;
	if (m == 0) {
		if (argc != 1) usage();
		clear = argv[0];
		if (salt.s == 0)
			getsalt(&salt, 32);
		feed_salt(salt.s, salt.len);
		feed_crypt(cformat);
		for (i = 0; mode[i] != 0; i++) {
			if (make_passwd(mode[i], clear, &pw) == OK) {
				stralloc_0(&pw);
				printf("%s%s\n", mode[i], pw.s);
			} else
				printf("%s failed.\n", mode[i]);
		}
	} else {
		if (argc != 2) usage();
		clear = argv[0];
		encrypted = argv[1];
		switch(cmp_passwd(clear, encrypted)) {
		case OK:
			printf("passwords are equal.\n");
			break;
		case BADPASS:
			printf("passwords are NOT equal.\n");
			break;
		case ERRNO:
			printf("digest: cmp_passwd: %s.\n", error_str(errno));
			exit(1);
		case ILLVAL:
			printf("digest: cmp_password: "
			    "illegal hashed password.\n");
			exit(1);
		default:
			printf("digest: cmp_password: failed.");
			exit(1);
		}
	}
	
	exit(0);
}

