/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SHA512_32H
# define HEADER_SHA512_32H

#include <stdio.h>
#include <unistd.h>

void OPENSSL_cleanse(void *, size_t );


#ifdef  __cplusplus
extern "C" {
#endif

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

# define SHA_LONG unsigned int

# define SHA_LBLOCK      16
# define SHA_CBLOCK      (SHA_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
# define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
# define SHA_DIGEST_LENGTH 20

#ifdef THIRTY_TWO_BIT

typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

int SHA1_Init(SHA_CTX *);
int SHA1_Update(SHA_CTX *, const void *, size_t );
int SHA1_Final(unsigned char *, SHA_CTX *);
unsigned char *SHA1(const unsigned char *, size_t, unsigned char * );
void SHA1_Transform(SHA_CTX *, const unsigned char * );

# define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */

typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

int SHA224_Init(SHA256_CTX *);
int SHA224_Update(SHA256_CTX *, const void *, size_t );
int SHA224_Final(unsigned char *, SHA256_CTX * );
unsigned char *SHA224(const unsigned char *, size_t, unsigned char * );
int SHA256_Init(SHA256_CTX *);
int SHA256_Update(SHA256_CTX *, const void *, size_t );
int SHA256_Final(unsigned char *, SHA256_CTX *);
unsigned char *SHA256(const unsigned char *, size_t, unsigned char *);
void SHA256_Transform(SHA256_CTX *, const unsigned char *);

#endif  /* #ifdef THIRTY_TWO_BIT */


# define SHA224_DIGEST_LENGTH    28
# define SHA256_DIGEST_LENGTH    32
# define SHA384_DIGEST_LENGTH    48
# define SHA512_DIGEST_LENGTH    64

/*
 * 32-bit digest algorithms for the SHA-512 see sha512_32.c
 */

/*
#ifdef THIRTY_TWO_BIT
*/

typedef union {           /* # SHA_LONG32 has been written to the 32 bit */
   unsigned int  i[2];
   unsigned long l;       /* remove long long -> long to compile on VAX  */
   } SHA_LONG32;

# define SHA512_LBLOCK (SHA_LBLOCK*2)
# define SHA512_CBLOCK (SHA_LBLOCK*8)

/*
 * To check 32 bit create union
 * after check delete 64 bit long long
 */

typedef struct SHA512_32state_st {
    SHA_LONG32 h[8];
    SHA_LONG32 Nl, Nh;
    union {
        SHA_LONG32 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_32CTX;

int SHA384_32Init(SHA512_32CTX *);
int SHA384_32Update(SHA512_32CTX *, const void *, size_t );
int SHA384_32Final(unsigned char *, SHA512_32CTX *);
unsigned char *SHA384_32(const unsigned char *, size_t, unsigned char * );

char *SHA384_32End(SHA512_32CTX *, char *);
char *SHA384_32Fd(int, char *);
char *SHA384_32FdChunk(int, char *, off_t, off_t);
char *SHA384_32File(const char *, char *);
char *SHA384_32FileChunk(const char *, char *, off_t, off_t);
char *SHA384_32Data(const void *, unsigned int, char *);

int SHA512_32Init(SHA512_32CTX *);
int SHA512_224_32Init(SHA512_32CTX *);
int SHA512_256_32Init(SHA512_32CTX *);
int SHA512_32Update(SHA512_32CTX *, const void *, size_t );
int SHA512_32Final(unsigned char *, SHA512_32CTX *);
unsigned char *SHA512t256_32(const unsigned char *, size_t, unsigned char * );
unsigned char *SHA512_32(const unsigned char *, size_t, unsigned char * );

void SHA512_32Transform(SHA512_32CTX *, const unsigned char * );

char *SHA512_32End(SHA512_32CTX *, char *);
char *SHA512_32Fd(int, char *);
char *SHA512_32FdChunk(int, char *, off_t, off_t);
char *SHA512_32File(const char *, char *);
char *SHA512_32FileChunk(const char *, char *, off_t, off_t);
char *SHA512_32Data(const void *, unsigned int, char *);

char *SHA512t256_32End(SHA512_32CTX *, char *);
char *SHA512t256_32Fd(int, char *);
char *SHA512t256_32FdChunk(int, char *, off_t, off_t);
char *SHA512t256_32File(const char *, char *);
char *SHA512t256_32FileChunk(const char *, char *, off_t, off_t);
char *SHA512t256_32Data(const void *, unsigned int, char *);

char *SHA512t224_32End(SHA512_32CTX *, char *);
char *SHA512t224_32Fd(int, char *);
char *SHA512t224_32FdChunk(int, char *, off_t, off_t);
char *SHA512t224_32File(const char *, char *);
char *SHA512t224_32FileChunk(const char *, char *, off_t, off_t);
char *SHA512t224_32Data(const void *, unsigned int, char *);

/*
#endif   THIRTY_TWO_BIT
*/

#ifdef  __cplusplus
}
#endif

#endif  /* ifndef HEADER_SHA512_32H */
