/* digest_rmd160.h for QLDAP checkpassword.c */

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

/* structure definitions */

typedef struct {
        u_int32_t state[5];     /* state (ABCDE) */
        u_int32_t length[2];    /* number of bits */
        unsigned char  bbuffer[64];    /* overflow buffer */
        u_int32_t buflen;       /* number of chars in bbuffer */
} RMD160_CTX;

/********************************************************************/

/* function prototypes */

void RMD160Init __P((RMD160_CTX *context));
void RMD160Transform __P((u_int32_t state[5], const u_int32_t block[16]));
void RMD160Update __P((RMD160_CTX *context, const unsigned char *data, unsigned int nbytes));
void RMD160Final __P((unsigned char digest[20], RMD160_CTX *context));
char *RMD160End __P((RMD160_CTX *, char *));
char *RMD160File __P((char *, char *));
char *RMD160Data __P((const unsigned char *, size_t, char *));

char *RMD160DataBase64 __P((const unsigned char *, size_t, char *, size_t));

#endif  /* _RMD160_H */
