/* digest_md5.h for QLDAP modified to use djb's stuff */

/*        */
/*  MD5   */
/*        */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#ifndef _MD5_H_
#define _MD5_H_

#include "uint32.h"

/* MD5 context. */
typedef struct MD5Context {
    uint32 state[4];            /* state (ABCD) */
    uint32 count[2];            /* number of bits, modulo 2^64 */
    unsigned char buffer[64];   /* input buffer */
} MD5_CTX;

void   MD5Init ();
void   MD5Update ();
void   MD5Final ();
char  *MD5End ();
char  *MD5Data ();

char  *MD5DataBase64 ();

int    ns_mta_hash_alg();
int    ns_mta_md5_cmp_pw();

#endif /* _MD5_H_ */
