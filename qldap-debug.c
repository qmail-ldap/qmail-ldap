/* qldap-debug.c, jeker@n-r-g.com, best viewed with tabsize = 4 */
#include "output.h"
#include "qldap-debug.h"
#include "env.h"
#include "scan.h"
#include "readwrite.h"

#include <stdarg.h>

#ifdef ENABLE_PROFILE
#include <taia.h>
#endif

#ifdef DEBUG

/* 
 * Known LOGLEVELs: 
 *  1 = Error, only errors are reported (not verbose)
 *  2 = Warning, errors and warnings are reported (normaly not verbose)
 *  4 = Info, print some information (login name and success or fail)
 *  8 = Info^2 (more info), session forwarding and maildirmake ...
 * 16 = Debug, more information about authentication etc.
 * 32 = Debug^2 (more debug info), even more ...
 * 64 = LDAP-Debug, show everything in the ldap-module
 *128 = some more LDAP-Debug stuff (good for ldap test tool)
 *256 = PASSWD-Debug, this shows the encrypted and clear text passwords
 *      so use it with care 
 *1024= profiling output (if compiled with profile support)
 */

#define LOGLEN 256
static int addLOG;
static unsigned long loglevel;
substdio sslog;
char logbuffer[LOGLEN];

void
log_init(int fd, unsigned long mask, int via_spawn)
/* 
 * Known LOGLEVELs: 
 */
{
	char *a = env_get("LOGLEVEL");
	
	loglevel = 0;
	addLOG = via_spawn;
	if ( a && *a ) {
		scan_ulong(a, &loglevel);
	} else if ((a = env_get("DEBUGLEVEL")) && *a ) {
		scan_ulong(a, &loglevel);
	}
	loglevel &= mask;

	substdio_fdbuf(&sslog, subwrite, fd, logbuffer, sizeof(logbuffer) );
/*	log(4, "LOGLEVEL set to %i\n", loglevel);
 */
}

void
log(unsigned long level, const char *fmt, ...)
/* see va_output (output.c) */
{
	va_list ap;
	char ch;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	ch = 15;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
	ch = 16;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	if ( substdio_flush(&sslog) == -1 ) return;
}

/* use logstart, logadd and logend with care, if there is no corresponding
   start or end starnge messages will be loged or some important messages 
   will be lost */
void
logstart(unsigned long level, const char *fmt, ...)
{
	va_list ap;
	char ch;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	ch = 15;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
}

void
logadd(unsigned long level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
}

void
logend(unsigned long level, const char *fmt, ...)
{
	va_list ap;
	char ch;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
	ch = 16;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	if ( substdio_flush(&sslog) == -1 ) return;
}

void
profile(const char *s)
{
#ifdef ENABLE_PROFILE
	char buf[TAIA_PACK];
	struct taia t;

	taia_now(&t);
	taia_pack(buf,&t);
	log(LOG_PROFILE, "PROFILE: %s @%s\n", s, buf); 
#endif
}
#else /* DEBUG */
void log_init(int fd, unsigned long mask, int via_spawn) {}
void log(unsigned long level, const char *fmt, ...) {}
void logstart(unsigned long level, const char *fmt, ...) {}
void logadd(unsigned long level, const char *fmt, ...) {}
void logend(unsigned long level, const char *fmt, ...) {}
void profile(const char *s) {}
#endif
