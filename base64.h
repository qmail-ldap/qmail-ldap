#ifndef __BASE64_H__
#define __BASE64_H__
/* base64.h for QLDAP modified to use only djb's qmail stuff */

#include "stralloc.h"

/*        *
 * BASE64 *
 *        */

/* base63 encode */
int b64_ntop(unsigned char const *, size_t, char *, size_t);

/* base64 decode */
int b64_pton(char const *, unsigned char *, size_t);

/* the same as above but this time with a stralloc as destination */
int b64_ntops(unsigned char const *, size_t , stralloc *);

/* the same as above but this time with a stralloc as destination */
int b64_ptons(char const *, stralloc *);

#define BASE64_NTOP_LEN(x)      (((x)+2)/3 * 4 + 1)
#define BASE64_PTON_LEN(x)      (((x)+3)/4 * 3 + 1)

int hex_ntops(unsigned char const *, size_t, stralloc *);
int hex_ptons(char const *, stralloc *);

#endif
