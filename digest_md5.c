/* digest_md5.c for QLDAP modified to use djb's stuff  */
/* contains MD5 algorithm stolen directly from OpenBSD */

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

#include <sys/types.h>
#include "uint32.h"
#include "byte.h"
#include "digest_md5.h"
#include "base64.h"
#include "stralloc.h"
#include "str.h"

/* some systems don't have NULL defined */
#ifndef NULL
#define NULL (void*) 0
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform ();

#ifdef __LITTLE_ENDIAN__
#define Encode byte_copy
#define Decode byte_copy
#else  /* __BIG_ENDIAN__ */
static void Encode ();
static void Decode ();
#endif /* __LITTLE_ENDIAN__ */

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

#ifdef __BIG_ENDIAN__
/* Encodes input (uint32) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void Encode (out, len, in)
void *out;
size_t len;
const void *in;
{
  unsigned char *output = out;
  size_t i, j;
  const uint32 *input = in;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (unsigned char)(input[i] & 0xff);
    output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
    output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
    output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (uint32). Assumes len is
  a multiple of 4.
 */
static void Decode (out, len, in)
void *out;
size_t len;
const void *in;
{
  uint32 *output = out;
  const unsigned char *input = in;
  size_t i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint32)input[j]) | (((uint32)input[j+1]) << 8) |
    (((uint32)input[j+2]) << 16) | (((uint32)input[j+3]) << 24);
}
#endif /* __BIG_ENDIAN__ */

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void MD5Init (context)
MD5_CTX *context;                                        /* context */
{
  context->count[0] = 0;
  context->count[1] = 0;

  /* Load magic initialization constants. */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void MD5Update (context, input, inputLen)
MD5_CTX *context;                                       /* context */
const unsigned char *input;                             /* input block */
size_t inputLen;                     /* length of input block */
{
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ( (context->count[0] += ((uint32)inputLen << 3)) /* lower part of count */
       < ((uint32)inputLen << 3) )
    context->count[1]++; /* low part of count overflowed */

  context->count[1] += ((uint32)inputLen >> 29); /* update high part of count */

  partLen = 64 - index;

  /* Transform as many times as possible. */
  if (inputLen >= partLen) {
    byte_copy ((POINTER)&context->buffer[index], partLen, (POINTER)input);
    MD5Transform (context->state, context->buffer);

    for (i = partLen; i + 63 < inputLen; i += 64)
      MD5Transform (context->state, &input[i]);

    index = 0;
  }
  else
    i = 0;

  /* Buffer remaining input */
  byte_copy ((POINTER)&context->buffer[index], inputLen-i, (POINTER)&input[i]);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void MD5Final (digest, context)
unsigned char digest[16];                         /* message digest */
MD5_CTX *context;                                       /* context */
{
  unsigned char bits[8];
  unsigned int index;
  size_t padLen;
  uint32 hi, lo;

  /* Save number of bits */
  hi = context->count[1];
  lo = context->count[0];
  Encode (bits, 4, &lo);
  Encode (bits + 4, 4, &hi);

  /* Pad out to 56 mod 64. */
  index = (unsigned int)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  if (digest != NULL) {
    /* Store state in digest */
    Encode (digest, 16, context->state);

    /* Zeroize sensitive information.  */
    byte_zero ((POINTER)context, sizeof (*context));
  }
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform (state, block)
uint32 state[4];
const unsigned char block[64];
{
  uint32 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode (x, 64, block);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information. */
  byte_zero ((POINTER)x, sizeof (x));
}

/* mdXhl.c
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dkuug.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

/* ARGSUSED */
char *
MD5End(ctx, buf)
    MD5_CTX *ctx;
    char *buf;
{
    int i;
    char *p = buf;
    unsigned char digest[16];
    static const char hex[]="0123456789abcdef";

    if (!p)
        return 0;
    MD5Final(digest,ctx);
    for (i=0;i<16;i++) {
        p[i+i] = hex[digest[i] >> 4];
        p[i+i+1] = hex[digest[i] & 0x0f];
    }
    p[i+i] = '\0';
    return p;
}

char *
MD5Data (data, len, buf)
    const unsigned char *data;
    size_t len;
    char *buf; /* XXX buf needs to be at least 33 Bytes big. */
{
    MD5_CTX ctx;

    MD5Init(&ctx);
    MD5Update(&ctx,data,len);
    return MD5End(&ctx, buf);
}

/* Base 64 */

char *
MD5DataBase64 (data, len, buf, buflen)
    const unsigned char *data;
    size_t len;
    char *buf; /* nedds to be 25 Bytes big */
    size_t buflen;
{
    MD5_CTX ctx;
    unsigned char buffer[16];

    MD5Init(&ctx);
    MD5Update(&ctx, data, len);
    MD5Final(buffer,&ctx);
    b64_ntop(buffer,sizeof(buffer),buf,buflen);
    return(buf);
}

/* Netscape MTA MD5 as found in Netscape MailServer < 2.02 and Software.com's
   Post.Office */

/* XXX this Netscape MTA MD5 implementation is absolutly ugly. I fixed the 
   possible buffer overflows, but this does not mean it is perfect
                                      Claudio Jeker jeker@n-r-g.com */

static char * ns_mta_hextab = "0123456789abcdef";

static void
ns_mta_hexify(char *buffer, char *str, int len)
/* normaly we should also tell the size of the buffer, this is implicitly done
   buffer is enough great to hold the 32 hexchars (sizeof(buffer) == 65) */
{
  char *pch = str;
  char ch;
  int i;

  for(i = 0;i < len; i ++) {
    ch = pch[i];
    buffer[2*i] = ns_mta_hextab[(ch>>4)&0xF];
    buffer[2*i+1] = ns_mta_hextab[ch&0xF];
  }

  return;
}

int
ns_mta_hash_alg(char *buffer, char *salt, char *passwd)
{
  MD5_CTX context;
  stralloc saltstr = {0};
  unsigned char digest[16], c;

  if (!stralloc_copys(&saltstr, salt) ) return -1; /* errno set by stralloc */
  c = 86;
  if (!stralloc_append(&saltstr, &c) ) return -1;
  if (!stralloc_cats(&saltstr, passwd) ) return -1;
  c = 247;
  if (!stralloc_cats(&saltstr, salt) ) return -1;
  if (!stralloc_0(&saltstr) ) return -1;
  /* the stralloc is not freed so we loose some memory (until exit) but
     this is better than the possible root exploit that was in the code before
   */
  
  MD5Init(&context);
  MD5Update(&context,(unsigned char *)saltstr.s,saltstr.len);
  MD5Final(digest,&context);
  ns_mta_hexify(buffer,(char*)digest,16);
  buffer[32] = '\0';
  return 0;
}

int
ns_mta_md5_cmp_pw(char * clear, char *mangled)
{
  char mta_hash[33];
  char mta_salt[33];
  char buffer[65];
  int  match;

  if ( str_len(mangled) != 64 ) return -1; /* XXX is this correct ??? */
  
  byte_copy(mta_hash,32,mangled);
  byte_copy(mta_salt,32,&mangled[32]);

  mta_hash[32] = mta_salt[32] = 0;
  if ( ns_mta_hash_alg(buffer,mta_salt,clear) ) return -1;
  match = str_diffn(mta_hash,buffer, 32);

  return(match);
}

