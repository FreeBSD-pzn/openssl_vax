/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SHA_H
# define HEADER_SHA_H

#include <stdio.h>
void OPENSSL_cleanse(void *ptr, size_t len);


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

typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);

# define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */

typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);

# define SHA224_DIGEST_LENGTH    28
# define SHA256_DIGEST_LENGTH    32
# define SHA384_DIGEST_LENGTH    48
# define SHA512_DIGEST_LENGTH    64

# define SHA512_LBLOCK (SHA_LBLOCK*2)
# define SHA512_CBLOCK (SHA_LBLOCK*8)

/*
 * To check 32 bit create union
 * after check delete 64 bit long long
 */

/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
/*
 * SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values.
 */
#  define SHA_LONG64 unsigned long long

typedef struct SHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;


int SHA384_Init(SHA512_CTX *);
int SHA384_Update(SHA512_CTX *, const void *, size_t );
int SHA384_Final(unsigned char *, SHA512_CTX * );
unsigned char *SHA384(const unsigned char *, size_t, unsigned char * );

int SHA512_Init(SHA512_CTX *);
int SHA512_Update(SHA512_CTX *, const void *, size_t );
int SHA512_Final(unsigned char *, SHA512_CTX * );
unsigned char *SHA512(const unsigned char *, size_t, unsigned char * );
void SHA512_Transform(SHA512_CTX *, const unsigned char * );

int SHA512_256_Init(SHA512_CTX * );
int SHA512_224_Init(SHA512_CTX * );


char *SHA512_End(SHA512_CTX *, char *);
char *SHA512_Fd(int, char *);
char *SHA512_FdChunk(int, char *, off_t, off_t);
char *SHA512_File(const char *, char *);
char *SHA512_FileChunk(const char *, char *, off_t, off_t);
char *SHA512_Data(const void *, unsigned int, char *);

char *SHA512t256_End(SHA512_CTX *, char *);
char *SHA512t256_Fd(int, char *);
char *SHA512t256_FdChunk(int, char *, off_t, off_t);
char *SHA512t256_File(const char *, char *);
char *SHA512t256_FileChunk(const char *, char *, off_t, off_t);
char *SHA512t256_Data(const void *, unsigned int, char *);

char *SHA512t224_End(SHA512_CTX *, char *);
char *SHA512t224_Fd(int, char *);
char *SHA512t224_FdChunk(int, char *, off_t, off_t);
char *SHA512t224_File(const char *, char *);
char *SHA512t224_FileChunk(const char *, char *, off_t, off_t);
char *SHA512t224_Data(const void *, unsigned int, char *);

int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);

char *SHA384_End(SHA512_CTX *, char *);
char *SHA384_Fd(int, char *);
char *SHA384_FdChunk(int, char *, off_t, off_t);
char *SHA384_File(const char *, char *);
char *SHA384_FileChunk(const char *, char *, off_t, off_t);
char *SHA384_Data(const void *, unsigned int, char *);


#ifdef  __cplusplus
}
#endif

#endif  /* ifndef HEADER_SHA_H */
