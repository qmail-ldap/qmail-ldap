/* digest_sha1.h for QLDAP modified to use djb stuff */

/*        */
/*  SHA1  */
/*        */

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef _SHA1_H
#define _SHA1_H

#include "uint32.h"

typedef struct {
    uint32 state[5];
    uint32 count[2];  
    unsigned char buffer[64];
} SHA1_CTX;
  
void SHA1Transform ();
void SHA1Init ();
void SHA1Update ();
void SHA1Final ();
char *SHA1End ();
char *SHA1Data ();

char *SHA1DataBase64 ();

#endif /* _SHA1_H */
