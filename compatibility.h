#ifndef __COMPATIBILITY_H__
#define __COMPATIBILITY_H__

/* compatibility.h a compatibility include for the qmail-ldap checkpasword    *
 * implementation. These nasty little differences of U*NXes a driving me nuts */


#ifndef __P
 #ifdef __STDC__
 #define __P(p)  p
 #else
 #define __P(p)  ()
 #endif
#endif


#ifdef sun /* some special treatments for SunOSes :-( */

#include <fcntl.h>

//typedef uint32_t u_int32_t;
//typedef uint64_t u_int64_t;
typedef u_longlong_t   u_int64_t;
typedef  unsigned int   u_int32_t;

#endif

#endif
