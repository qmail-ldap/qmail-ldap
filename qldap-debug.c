/* qldap-debug.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "stralloc.h"
#include "substdio.h"
#include "fmt.h"
#include "str.h"
#include "byte.h"
#include "qldap-errno.h"
#include "error.h"
#include "env.h"
#include "scan.h"
#include "readwrite.h"

#include <stdarg.h>

#ifdef DEBUG

#define DEBUGLEN 1024
char debugbuffer[DEBUGLEN];
char num[FMT_ULONG];
int  debfd;
int  dlevel;
substdio ssdeb;

static const char nullString[] = "(null pointer)";
static const char ioHexArray[16] =  {'0','1','2','3','4','5','6','7',
                                     '8','9','a','b','c','d','e','f'};
									 
static int fmt_hexulong(char *s, unsigned long x) {
	unsigned int i;
	
	byte_copy(s, 2, "0x");
	s += 2;
	for (i = 0; i < sizeof(unsigned long) * 2; i++) {
		*s++ = (ioHexArray[(x >> 28) & 0xf]);
		x = x << 4;
	}
	return ( sizeof(unsigned long) * 2 + 2 );
}
#endif

void debug(int level, char *fmt, ...)
/* works like printf has the format options %i, ...
 * all flags (#, 0, -, ' ', +, ' ... ) are not supported if not special noted
 * Also not supported are all options for foating-point numbers (not needed 
 * in qmail)
 * Supported conversion specifiers: diouxXcsSp%
 * diux are for integer (long) conversions
 * c is a single unsigned char
 * s is a zero terminated string
 * S is a stralloc object (should not be zero terminated (else the zero will
 * be printed))
 * p is the hex address of a generic pointer (void *)
 * % is the % sign */
{
#ifdef DEBUG
	va_list args;
	unsigned long ul;
	long l;
	char *s;
	char *start;
	char *cur;
	void *p;
	unsigned char c;
	stralloc *sa;

	if ( level > dlevel ) return;
	va_start(args,fmt);

	start = fmt;
	cur = fmt;
	while (*cur) {
		if (*cur == '%') {
			if ( substdio_put(&ssdeb, start, cur-start) == -1 ) return;
			cur++;
			switch (*cur) {
				case 'd':
				case 'i':
					l = va_arg(args, long);
					if ( l < 0 ) { /* negativ number, d and i are signed */
						l *= -1;
						if ( substdio_put(&ssdeb, "-", 1) == -1 ) return;
					}
					ul = (unsigned long) l;
					if ( substdio_put(&ssdeb, num, fmt_ulong(num, ul) ) ) 
						return;
					break;
				case 'u':
					ul = va_arg(args, unsigned long);
					if ( substdio_put(&ssdeb, num, fmt_ulong(num, ul) ) ) 
						return;
					break;
				case 's':
					s = va_arg(args, char *);
					if ( !s ) s = nullString;
					if ( substdio_put(&ssdeb, s, str_len(s) ) ) return;
					break;
				case 'S':
					sa = va_arg(args, stralloc *);
					if ( !sa ) {
						if ( substdio_put(&ssdeb, nullString, 
											str_len(nullString) ) )
							return;
						break;
					}
					if ( substdio_put(&ssdeb, sa->s, sa->len ) ) return;
					break;
				case '%':
					if ( substdio_put(&ssdeb, "%", 1) == -1 ) return;
					break;
				case 'p':
					p = va_arg(args, void *);
					ul = (unsigned long) p;
					if ( substdio_put(&ssdeb, num, fmt_hexulong(num, ul) ) ) 
						return;
					break;
				case 'x':
					ul = va_arg(args, unsigned long);
					if ( substdio_put(&ssdeb, num, fmt_hexulong(num, ul) ) ) 
						return;
					break;
				case 'c':
					c = va_arg(args, unsigned char);
					substdio_BPUTC(&ssdeb, c);
					break;
			}
			start = ++cur; 
		} else {
			cur++;
		}
	}
	if ( substdio_put(&ssdeb, start, cur-start) == -1 ) return;
	if ( substdio_flush(&ssdeb) == -1 ) return;
	va_end(args);
	
#endif /* DEBUG */
}

void init_debug(int fd, unsigned int maxlevel)
/* 
 * Known DEBUGLEVELs: 
 *  1 = Error, only errors are reported (not verbose)
 *  2 = Warning, errors and warnings are reported (normaly not verbose)
 *  4 = Info, print some information (login name and success or fail)
 *  8 = Info^2 (more info), session forwarding and maildirmake ...
 * 16 = Debug, more information about authentication etc.
 * 32 = Debug^2 (more debug info), even more ...
 * 64 = LDAP-Debug, show everything in the ldap-module
 *128 = PASSWD-Debug, this shows the encrypted and clear text passwords
 *      so use it with care */
{
#ifdef DEBUG
	char *a = env_get("DEBUGLEVEL");
	
	dlevel = 0;
	if ( a && *a ) {
		scan_ulong(a, &dlevel);
	}
	if ( dlevel > maxlevel ) dlevel = maxlevel;
	
	substdio_fdbuf(&ssdeb, write, fd, debugbuffer, sizeof(debugbuffer) );
	
#endif /* DEBUG */
}

char *qldap_err_str(int errno)
/* returns a string that corresponds to the qldap_errno */
{
#ifdef DEBUG
	switch (errno) {
		case ERRNO:
			return error_str(errno);
		case LDAP_INIT:
			return "initalizing of ldap connection faild";
		case LDAP_BIND:
			return "binding to ldap server faild";
		case LDAP_SEARCH:
			return "ldap_search faild";
		case LDAP_NOSUCH:
			return "no such object";
		case LDAP_REBIND:
			return "rebinding to ldap server faild";
		case LDAP_NEEDED:
			return "needed object/field is missing";
		case LDAP_COUNT:
			return "too many entries found";

		case AUTH_FAILD:
			return "authorization faild wrong password";
		case AUTH_ERROR:
			return "error on authentication";
		case ILL_PATH:
			return "illegal path";
		case ILL_AUTH:
			return "illegal authentication mode";
		case BADCLUSTER:
			return "bad settings for clustering";
		case ACC_DISABLED:
			return "account disabled";
		case AUTH_PANIC:
			return "unexpected event, PANIC";
		case AUTH_EXEC:
			return "unable to start subprogram";
			
		case MAILDIR_CORRUPT:
			return "maildir seems to be corrupted";
		case MAILDIR_CRASHED:
			return "dirmaker script crashed";
		case MAILDIR_BADEXIT:
			return "dirmaker exit status not zero";
		default:
			return "unknown error occured";
	}
#endif /* DEBUG */
}
