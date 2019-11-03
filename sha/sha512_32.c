/*
 * Copyright 2004-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* #include <openssl/opensslconf.h> */
/*-
 * IMPLEMENTATION NOTES.
 *
 * As you might have noticed 32-bit hash algorithms:
 *
 * - permit SHA_LONG to be wider than 32-bit
 * - optimized versions implement two transform functions: one operating
 *   on [aligned] data in host byte order and one - on data in input
 *   stream byte order;
 * - share common byte-order neutral collector and padding function
 *   implementations, ../md32_common.h;
 *
 * Neither of the above applies to this SHA-512 implementations. Reasons
 * [in reverse order] are:
 *
 * - it's the only 64-bit hash algorithm for the moment of this writing,
 *   there is no need for common collector/padding implementation [yet];
 * - by supporting only one transform function [which operates on
 *   *aligned* data in input stream byte order, big-endian in this case]
 *   we minimize burden of maintenance in two ways: a) collector/padding
 *   function is simpler; b) only one transform function to stare at;
 * - SHA_LONG64 is required to be exactly 64-bit in order to be able to
 *   apply a number of optimizations to mitigate potential performance
 *   penalties caused by previous design decision;
 *
 * Caveat lector.
 *
 * Implementation relies on the fact that "long long" is 64-bit on
 * both 32- and 64-bit platforms. If some compiler vendor comes up
 * with 128-bit long long, adjustment to sha.h would be required.
 * As this implementation relies on 64-bit integer type, it's totally
 * inappropriate for platforms which don't support it, most notably
 * 16-bit platforms.
 */
#include <stdlib.h>
#include <string.h>

/*
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#include "internal/cryptlib.h"
#include "internal/sha.h"
*/


/* ============================================= */
#include "sha_test.h"
/* ============================================= */



#if defined(__i386) || defined(__i386__) || defined(_M_IX86) || \
    defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64) || \
    defined(__s390__) || defined(__s390x__) || \
    defined(__aarch64__) || \
    defined(SHA512_ASM)
# define SHA512_BLOCK_CAN_MANAGE_UNALIGNED_DATA
#endif

int sha512_224_32init(SHA512_32CTX *c)
{
    c->h[0].i[1] = 0x8c3d37c8; c->h[0].i[0] = 0x19544da2;
    c->h[1].i[1] = 0x73e19966; c->h[1].i[0] = 0x89dcd4d6;
    c->h[2].i[1] = 0x1dfab7ae; c->h[2].i[0] = 0x32ff9c82;
    c->h[3].i[1] = 0x679dd514; c->h[3].i[0] = 0x582f9fcf;
    c->h[4].i[1] = 0x0f6d2b69; c->h[4].i[0] = 0x7bd44da8;
    c->h[5].i[1] = 0x77e36f73; c->h[5].i[0] = 0x04c48942;
    c->h[6].i[1] = 0x3f9d85a8; c->h[6].i[0] = 0x6a1d36c8;
    c->h[7].i[1] = 0x1112e6ad; c->h[7].i[0] = 0x91d692a1;

    c->Nl.i[1] = c->Nl.i[0] = 0;
    c->Nh.i[1] = c->Nh.i[0] = 0;
    c->num = 0;
    c->md_len = SHA224_DIGEST_LENGTH;
    return 1;
}

int sha512_256_32init(SHA512_32CTX *c)
{
    c->h[0].i[1] = 0x22312194; c->h[0].i[0] = 0xfc2bf72c;
    c->h[1].i[1] = 0x9f555fa3; c->h[1].i[0] = 0xc84c64c2;
    c->h[2].i[1] = 0x2393b86b; c->h[2].i[0] = 0x6f53b151;
    c->h[3].i[1] = 0x96387719; c->h[3].i[0] = 0x5940eabd;
    c->h[4].i[1] = 0x96283ee2; c->h[4].i[0] = 0xa88effe3;
    c->h[5].i[1] = 0xbe5e1e25; c->h[5].i[0] = 0x53863992;
    c->h[6].i[1] = 0x2b0199fc; c->h[6].i[0] = 0x2c85b8aa;
    c->h[7].i[1] = 0x0eb72ddc; c->h[7].i[0] = 0x81c52ca2;

    c->Nl.i[1] = c->Nl.i[0] = 0;
    c->Nh.i[1] = c->Nh.i[0] = 0;
    c->num = 0;
    c->md_len = SHA256_DIGEST_LENGTH;
    return 1;
}

int SHA384_32Init(SHA512_32CTX *c)
{
    c->h[0].i[1] = 0xcbbb9d5d; c->h[0].i[0] = 0xc1059ed8;
    c->h[1].i[1] = 0x629a292a; c->h[1].i[0] = 0x367cd507;
    c->h[2].i[1] = 0x9159015a; c->h[2].i[0] = 0x3070dd17;
    c->h[3].i[1] = 0x152fecd8; c->h[3].i[0] = 0xf70e5939;
    c->h[4].i[1] = 0x67332667; c->h[4].i[0] = 0xffc00b31;
    c->h[5].i[1] = 0x8eb44a87; c->h[5].i[0] = 0x68581511;
    c->h[6].i[1] = 0xdb0c2e0d; c->h[6].i[0] = 0x64f98fa7;
    c->h[7].i[1] = 0x47b5481d; c->h[7].i[0] = 0xbefa4fa4;

    c->Nl.i[1] = c->Nl.i[0] = 0;
    c->Nh.i[1] = c->Nh.i[0] = 0;
    c->num = 0;
    c->md_len = SHA384_DIGEST_LENGTH;
    return 1;
}

int SHA512_32Init(SHA512_32CTX *c)
{
    c->h[0].i[1] = 0x6a09e667; c->h[0].i[0] = 0xf3bcc908;
    c->h[1].i[1] = 0xbb67ae85; c->h[1].i[0] = 0x84caa73b;
    c->h[2].i[1] = 0x3c6ef372; c->h[2].i[0] = 0xfe94f82b;
    c->h[3].i[1] = 0xa54ff53a; c->h[3].i[0] = 0x5f1d36f1;
    c->h[4].i[1] = 0x510e527f; c->h[4].i[0] = 0xade682d1;
    c->h[5].i[1] = 0x9b05688c; c->h[5].i[0] = 0x2b3e6c1f;
    c->h[6].i[1] = 0x1f83d9ab; c->h[6].i[0] = 0xfb41bd6b;
    c->h[7].i[1] = 0x5be0cd19; c->h[7].i[0] = 0x137e2179;

    c->Nl.i[1] = c->Nl.i[0] = 0;
    c->Nh.i[1] = c->Nh.i[0] = 0;
    c->num = 0;
    c->md_len = SHA512_DIGEST_LENGTH;
    return 1;
}

/* static void sha512_32block_data_order(SHA512_32CTX *ctx, const void *in, size_t num);
 */
void sha512_32block_data_order(SHA512_32CTX *ctx, const void *in, size_t num);

/*
   WORK THERE
 */



int SHA512_32Final(unsigned char *md, SHA512_32CTX *c)
{
    unsigned char *p = (unsigned char *)c->u.p;
    size_t n = c->num;

    p[n] = 0x80;                /* There always is a room for one */
    n++;
    if (n > (sizeof(c->u) - 16)) {
        memset(p + n, 0, sizeof(c->u) - n);
        n = 0;
        sha512_32block_data_order(c, p, 1);
    }

    memset(p + n, 0, sizeof(c->u) - 16 - n);
#ifdef  B_ENDIAN
    c->u.d[SHA_LBLOCK - 2].i[0] = c->Nh.i[0];
    c->u.d[SHA_LBLOCK - 2].i[1] = c->Nh.i[1];

    c->u.d[SHA_LBLOCK - 1].i[0] = c->Nl.i[0];
    c->u.d[SHA_LBLOCK - 1].i[1] = c->Nl.i[1];
#else
    p[sizeof(c->u) - 1] = (unsigned char)(c->Nl.i[0]);        /*   (c->Nl)        */
    p[sizeof(c->u) - 2] = (unsigned char)(c->Nl.i[0]>>8);     /*   (c->Nl >> 8)   */
    p[sizeof(c->u) - 3] = (unsigned char)(c->Nl.i[0]>>16);    /*   (c->Nl >> 16)  */
    p[sizeof(c->u) - 4] = (unsigned char)(c->Nl.i[0]>>24);    /*   (c->Nl >> 24)  */
    p[sizeof(c->u) - 5] = (unsigned char)(c->Nl.i[1]);        /*   (c->Nl >> 32)  */
    p[sizeof(c->u) - 6] = (unsigned char)(c->Nl.i[1]>>8);     /*   (c->Nl >> 40)  */
    p[sizeof(c->u) - 7] = (unsigned char)(c->Nl.i[1]>>16);    /*   (c->Nl >> 48)  */
    p[sizeof(c->u) - 8] = (unsigned char)(c->Nl.i[1]>>24);    /*   (c->Nl >> 56)  */
    p[sizeof(c->u) - 9] = (unsigned char)(c->Nh.i[0]);        /*   (c->Nh)        */
    p[sizeof(c->u) - 10] = (unsigned char)(c->Nh.i[0]>>8);    /*   (c->Nh >> 8)   */
    p[sizeof(c->u) - 11] = (unsigned char)(c->Nh.i[0]>>16);   /*   (c->Nh >> 16)  */
    p[sizeof(c->u) - 12] = (unsigned char)(c->Nh.i[0]>>24);   /*   (c->Nh >> 24)  */
    p[sizeof(c->u) - 13] = (unsigned char)(c->Nh.i[1]);       /*   (c->Nh >> 32)  */
    p[sizeof(c->u) - 14] = (unsigned char)(c->Nh.i[1]>>8);    /*   (c->Nh >> 40)  */
    p[sizeof(c->u) - 15] = (unsigned char)(c->Nh.i[1]>>16);   /*   (c->Nh >> 48)  */
    p[sizeof(c->u) - 16] = (unsigned char)(c->Nh.i[1]>>24);   /*   (c->Nh >> 56)  */
#endif

    sha512_32block_data_order(c, p, 1);

    if (md == 0)
        return 0;

    switch (c->md_len) {
    /* Let compiler decide if it's appropriate to unroll... */
    case SHA224_DIGEST_LENGTH:
        for (n = 0; n < SHA224_DIGEST_LENGTH / 8; n++) {
            SHA_LONG32 t;                               /* SHA_LONG64 t = c->h[n] */
            t.i[1] = c->h[n].i[1];
            t.i[0] = c->h[n].i[0];
            *(md++) = (unsigned char)(t.i[1] >> 24);    /* (t >> 56)  */ 
            *(md++) = (unsigned char)(t.i[1] >> 16);    /* (t >> 48)  */
            *(md++) = (unsigned char)(t.i[1] >> 8);     /* (t >> 40)  */
            *(md++) = (unsigned char)(t.i[1]);          /* (t >> 32)  */
            *(md++) = (unsigned char)(t.i[0] >> 24);    /* (t >> 24)  */
            *(md++) = (unsigned char)(t.i[0] >> 16);    /* (t >> 16)  */
            *(md++) = (unsigned char)(t.i[0] >> 8);     /* (t >> 8)   */
            *(md++) = (unsigned char)(t.i[0]);          /* (t)        */
        }
        /*
         * For 224 bits, there are four bytes left over that have to be
         * processed separately.
         */
        {
        /*  SHA_LONG64 t = c->h[SHA224_DIGEST_LENGTH / 8]; */
            SHA_LONG32 t;
            t.i[1] = c->h[SHA224_DIGEST_LENGTH / 8].i[1];
            t.i[0] = c->h[SHA224_DIGEST_LENGTH / 8].i[0];

            *(md++) = (unsigned char)(t.i[1] >> 24);    /* (t >> 56)  */
            *(md++) = (unsigned char)(t.i[1] >> 16);    /* (t >> 48)  */
            *(md++) = (unsigned char)(t.i[1] >> 8);     /* (t >> 40)  */
            *(md++) = (unsigned char)(t.i[1]);          /* (t >> 32)  */
        }
        break;
    case SHA256_DIGEST_LENGTH:
        for (n = 0; n < SHA256_DIGEST_LENGTH / 8; n++) {
            SHA_LONG32 t;                               /* SHA_LONG64 t = c->h[n] */
            t.i[1] = c->h[n].i[1];
            t.i[0] = c->h[n].i[0];
            *(md++) = (unsigned char)(t.i[1] >> 24);    /* (t >> 56)  */ 
            *(md++) = (unsigned char)(t.i[1] >> 16);    /* (t >> 48)  */
            *(md++) = (unsigned char)(t.i[1] >> 8);     /* (t >> 40)  */
            *(md++) = (unsigned char)(t.i[1]);          /* (t >> 32)  */
            *(md++) = (unsigned char)(t.i[0] >> 24);    /* (t >> 24)  */
            *(md++) = (unsigned char)(t.i[0] >> 16);    /* (t >> 16)  */
            *(md++) = (unsigned char)(t.i[0] >> 8);     /* (t >> 8)   */
            *(md++) = (unsigned char)(t.i[0]);          /* (t)        */
        }
        break;
    case SHA384_DIGEST_LENGTH:
        for (n = 0; n < SHA384_DIGEST_LENGTH / 8; n++) {
            SHA_LONG32 t;                               /* SHA_LONG64 t = c->h[n] */
            t.i[1] = c->h[n].i[1];
            t.i[0] = c->h[n].i[0];
            *(md++) = (unsigned char)(t.i[1] >> 24);    /* (t >> 56)  */ 
            *(md++) = (unsigned char)(t.i[1] >> 16);    /* (t >> 48)  */
            *(md++) = (unsigned char)(t.i[1] >> 8);     /* (t >> 40)  */
            *(md++) = (unsigned char)(t.i[1]);          /* (t >> 32)  */
            *(md++) = (unsigned char)(t.i[0] >> 24);    /* (t >> 24)  */
            *(md++) = (unsigned char)(t.i[0] >> 16);    /* (t >> 16)  */
            *(md++) = (unsigned char)(t.i[0] >> 8);     /* (t >> 8)   */
            *(md++) = (unsigned char)(t.i[0]);          /* (t)        */
        }
        break;
    case SHA512_DIGEST_LENGTH:
        for (n = 0; n < SHA512_DIGEST_LENGTH / 8; n++) {
            SHA_LONG32 t;                               /* SHA_LONG64 t = c->h[n] */
            t.i[1] = c->h[n].i[1];
            t.i[0] = c->h[n].i[0];
            *(md++) = (unsigned char)(t.i[1] >> 24);    /* (t >> 56)  */ 
            *(md++) = (unsigned char)(t.i[1] >> 16);    /* (t >> 48)  */
            *(md++) = (unsigned char)(t.i[1] >> 8);     /* (t >> 40)  */
            *(md++) = (unsigned char)(t.i[1]);          /* (t >> 32)  */
            *(md++) = (unsigned char)(t.i[0] >> 24);    /* (t >> 24)  */
            *(md++) = (unsigned char)(t.i[0] >> 16);    /* (t >> 16)  */
            *(md++) = (unsigned char)(t.i[0] >> 8);     /* (t >> 8)   */
            *(md++) = (unsigned char)(t.i[0]);          /* (t)        */
        }
        break;
    /* ... as well as make sure md_len is not abused. */
    default:
        return 0;
    }

    return 1;
}

int SHA384_32Final(unsigned char *md, SHA512_32CTX *c)
{
    return SHA512_32Final(md, c);
}


extern void shift_left( SHA_LONG32 *p, unsigned int n);
extern void shift_rigth( SHA_LONG32 *p, unsigned int n);
extern void sum_uu( SHA_LONG32 *s, SHA_LONG32 *a, SHA_LONG32 *b );

int SHA512_32Update(SHA512_32CTX *c, const void *_data, size_t len)
{
/*    SHA_LONG64 l;
 */
    SHA_LONG32 l, tmp_len;
    size_t n;
    unsigned char *p = c->u.p;
    const unsigned char *data = (const unsigned char *)_data;

    if (len == 0)
        return 1;

/*    l = (c->Nl + (((SHA_LONG64) len) << 3)) & 0xffffffffffffffff;
 *    A question:
 *    Is it need & 0xffffffffffffffff ?
 *    I guess that:    a = b & 0xffffffffffffffff
 *    always will be   a = b
 */

/*   Need:
 *         shift_left( unsigned int *p, unsigned int n )
 *         shift_rigth( unsigned int *p, unsigned int n )
 *         plus_plus( unsigned int *p )
 *         minus_minus( unsigned int *p )
 *         if_less( unsigned int *a, unsigned int *b )
 *         if_more( unsigned int *a, unsigned int *b )
 */


    tmp_len.i[1] = 0x0;                /* replace (SHA_LONG64) len         */
    tmp_len.i[0] = len;
    shift_left( &tmp_len, 3 );         /* len << 3                         */
    sum_uu( &l, &(c->Nl), &tmp_len );  /* do not need & 0xffffffffffffffff */


/*    if (l < c->Nl)
        c->Nh++;
 */

    /* 
     * Is it possible on a only 32 bit implementations ?
     * on a 32 bit sizeof(len) will be always < 8
     */
/*    if (sizeof(len) >= 8)
        c->Nh += (((SHA_LONG64) len) >> 61);
 */
    c->Nl.i[1] = l.i[1];        /*   c->Nl = l    */
    c->Nl.i[0] = l.i[0];

    if (c->num != 0) {
        /* remove declaration to a begining of function */
        n = sizeof(c->u) - c->num;

        if (len < n) {
            memcpy(p + c->num, data, len), c->num += (unsigned int)len;
            return 1;
        } else {
            memcpy(p + c->num, data, n), c->num = 0;
            len -= n, data += n;
            sha512_32block_data_order(c, p, 1);
        }
    }

    if (len >= sizeof(c->u)) {
#ifndef SHA512_BLOCK_CAN_MANAGE_UNALIGNED_DATA
        if ((size_t)data % sizeof(c->u.d[0]) != 0)
            while (len >= sizeof(c->u))
                memcpy(p, data, sizeof(c->u)),
                sha512_32block_data_order(c, p, 1),
                len -= sizeof(c->u), data += sizeof(c->u);
        else
#endif
            sha512_32block_data_order(c, data, len / sizeof(c->u)),
            data += len, len %= sizeof(c->u), data -= len;
    }

    if (len != 0)
        memcpy(p, data, len), c->num = (int)len;

    return 1;
}

int SHA384_32Update(SHA512_32CTX *c, const void *data, size_t len)
{
    return SHA512_32Update(c, data, len);
}

void SHA512_32Transform(SHA512_32CTX *c, const unsigned char *data)
{
#ifndef SHA512_BLOCK_CAN_MANAGE_UNALIGNED_DATA
    if ((size_t)data % sizeof(c->u.d[0]) != 0)
        memcpy(c->u.p, data, sizeof(c->u.p)), data = c->u.p;
#endif
    sha512_32block_data_order(c, data, 1);
}

unsigned char *SHA384_32(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA512_32CTX c;
    static unsigned char m[SHA384_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    SHA384_32Init(&c);
    SHA512_32Update(&c, d, n);
    SHA512_32Final(md, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    return md;
}

unsigned char *SHA512_32(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA512_32CTX c;
    static unsigned char m[SHA512_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    SHA512_32Init(&c);
    SHA512_32Update(&c, d, n);
    SHA512_32Final(md, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    return md;
}

#ifndef SHA512_ASM

/**********************************************************************/

static const unsigned int K512_32[80][2] = {
     {0xd728ae22, 0x428a2f98},  {0x23ef65cd, 0x71374491},
     {0xec4d3b2f, 0xb5c0fbcf},  {0x8189dbbc, 0xe9b5dba5},
     {0xf348b538, 0x3956c25b},  {0xb605d019, 0x59f111f1},
     {0xaf194f9b, 0x923f82a4},  {0xda6d8118, 0xab1c5ed5},
     {0xa3030242, 0xd807aa98},  {0x45706fbe, 0x12835b01},
     {0x4ee4b28c, 0x243185be},  {0xd5ffb4e2, 0x550c7dc3},
     {0xf27b896f, 0x72be5d74},  {0x3b1696b1, 0x80deb1fe},
     {0x25c71235, 0x9bdc06a7},  {0xcf692694, 0xc19bf174},
     {0x9ef14ad2, 0xe49b69c1},  {0x384f25e3, 0xefbe4786},
     {0x8b8cd5b5, 0x0fc19dc6},  {0x77ac9c65, 0x240ca1cc},

     {0x592b0275, 0x2de92c6f},  {0x6ea6e483, 0x4a7484aa},
     {0xbd41fbd4, 0x5cb0a9dc},  {0x831153b5, 0x76f988da},
     {0xee66dfab, 0x983e5152},  {0x2db43210, 0xa831c66d},
     {0x98fb213f, 0xb00327c8},  {0xbeef0ee4, 0xbf597fc7},
     {0x3da88fc2, 0xc6e00bf3},  {0x930aa725, 0xd5a79147},
     {0xe003826f, 0x06ca6351},  {0x0a0e6e70, 0x14292967},
     {0x46d22ffc, 0x27b70a85},  {0x5c26c926, 0x2e1b2138},
     {0x5ac42aed, 0x4d2c6dfc},  {0x9d95b3df, 0x53380d13},
     {0x8baf63de, 0x650a7354},  {0x3c77b2a8, 0x766a0abb},
     {0x47edaee6, 0x81c2c92e},  {0x1482353b, 0x92722c85},

     {0x4cf10364, 0xa2bfe8a1},  {0xbc423001, 0xa81a664b},
     {0xd0f89791, 0xc24b8b70},  {0x0654be30, 0xc76c51a3},
     {0xd6ef5218, 0xd192e819},  {0x5565a910, 0xd6990624},
     {0x5771202a, 0xf40e3585},  {0x32bbd1b8, 0x106aa070},
     {0xb8d2d0c8, 0x19a4c116},  {0x5141ab53, 0x1e376c08},
     {0xdf8eeb99, 0x2748774c},  {0xe19b48a8, 0x34b0bcb5},
     {0xc5c95a63, 0x391c0cb3},  {0xe3418acb, 0x4ed8aa4a},
     {0x7763e373, 0x5b9cca4f},  {0xd6b2b8a3, 0x682e6ff3},
     {0x5defb2fc, 0x748f82ee},  {0x43172f60, 0x78a5636f},
     {0xa1f0ab72, 0x84c87814},  {0x1a6439ec, 0x8cc70208},

     {0x23631e28, 0x90befffa},  {0xde82bde9, 0xa4506ceb},
     {0xb2c67915, 0xbef9a3f7},  {0xe372532b, 0xc67178f2},
     {0xea26619c, 0xca273ece},  {0x21c0c207, 0xd186b8c7},
     {0xcde0eb1e, 0xeada7dd6},  {0xee6ed178, 0xf57d4f7f},
     {0x72176fba, 0x06f067aa},  {0xa2c898a6, 0x0a637dc5},
     {0xbef90dae, 0x113f9804},  {0x131c471b, 0x1b710b35},
     {0x23047d84, 0x28db77f5},  {0x40c72493, 0x32caab7b},
     {0x15c9bebc, 0x3c9ebe0a},  {0x9c100d4c, 0x431d67c4},
     {0xcb3e42b6, 0x4cc5d4be},  {0xfc657e2a, 0x597f299c},
     {0x3ad6faec, 0x5fcb6fab},  {0x4a475817, 0x6c44198c}
};

#endif    /* ifndef SHA512_ASM */



/*****************************
       WORK HERE
*****************************/
void get_K512_32( SHA_LONG32 *value, unsigned int cnt )
{
  if( cnt < 80 )
    {
     value->i[1] = K512_32[cnt][1];
     value->i[0] = K512_32[cnt][0];
    }
  else
    {
     value->i[1] = 0;
     value->i[0] = 0;
    }
}


void sha512_32block_data_order(SHA512_32CTX *ctx, const void *in, size_t num)
{
  SHA_LONG32 tmp;
  tmp.i[0] = K512_32[0][0];
  tmp.i[1] = K512_32[0][1];
}

