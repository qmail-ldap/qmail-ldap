/* qldap-debug.h, jeker@n-r-g.com, best viewed with tabsize = 4 */
#ifndef __QLDAP_DEBUG_H__
#define __QLDAP_DEBUG_H__

#define STDERR 2
#define STDOUT 1

void debug(int level, char *fmt, ...);
/* works like printf has the format options %i, ...
 * all flags (#, 0, -, ' ', +, ' ... ) are not supported
 * Also not supported are all options for foating-point numbers (not needed in qmail)
 * Supported conversion specifiers: diuxcsSp%
 * diux are for integer (long) conversions (di are signed all other unsigned)
 * c is a single unsigned char
 * s is a zero terminated string
 * S is a stralloc object (should not be zero terminated (else the zero will be printed))
 * p is the hex address of a generic pointer (void *)
 * % is the % sign */

void init_debug(int fd, unsigned int maxlevel);
/* reads the DEBUGLEVEL env var and sets the corresponding debuglevel */

char* qldap_err_str(int errno);
/* returns a string that corresponds to the qldap_errno */

#endif

