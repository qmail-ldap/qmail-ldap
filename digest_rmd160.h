/* digest_rmd160.h for QLDAP modified to use djb's stuff */

/*        */
/* RMD160 */
/*        */

/********************************************************************\
 *
 *      FILE:     rmd160.h
 *
 *      CONTENTS: Header file for a sample C-implementation of the
 *                RIPEMD-160 hash-function. 
 *      TARGET:   any computer with an ANSI C compiler
 *
 *      AUTHOR:   Antoon Bosselaers, ESAT-COSIC
 *      DATE:     1 March 1996
 *      VERSION:  1.0
 *
 *      Copyright (c) Katholieke Universiteit Leuven
 *      1996, All Rights Reserved
 *
\********************************************************************/

#ifndef  _RMD160_H      /* make sure this file is read only once */
#define  _RMD160_H

/********************************************************************/
#include "uint32.h"

/* structure definitions */

typedef struct {
        uint32 state[5];     /* state (ABCDE) */
        uint32 length[2];    /* number of bits */
        unsigned char  bbuffer[64];    /* overflow buffer */
        uint32 buflen;       /* number of chars in bbuffer */
} RMD160_CTX;

/********************************************************************/

/* function prototypes */

void RMD160Init ();
void RMD160Transform ();
void RMD160Update ();
void RMD160Final ();
char *RMD160End ();
char *RMD160Data ();

char *RMD160DataBase64 ();

#endif  /* _RMD160_H */
