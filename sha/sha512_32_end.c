/*
 *
 *
 *
 */

#include <stdio.h>
#include "sha_test.h"

extern unsigned int *K512_32[];
extern SHA_LONG64 *K512[];


/* Analog logical OR - |
 * s = l | r
 *
 * where l - SHA_LONG32
 *       r - SHA_LONG32
 *
 * result into s
 *
 */

SHA_LONG32 * sor32_64( SHA_LONG32 *s, SHA_LONG32 *l, SHA_LONG32 *r )
{
  s->i[0] = l->i[0] | r->i[0];
  s->i[1] = l->i[1] | r->i[1];

  return s;
}


/* Analog logical AND - &
 * s = l & r
 *
 * where l - SHA_LONG32
 *       r - SHA_LONG32
 *
 * result into s
 *
 */

SHA_LONG32 * sand32_64( SHA_LONG32 *s, SHA_LONG32 *l, SHA_LONG32 *r )
{
  s->i[0] = l->i[0] & r->i[0];
  s->i[1] = l->i[1] & r->i[1];

  return s;
}



/* Analog logical ^
 * s = l ^ r
 *
 * where l - SHA_LONG32
 *       r - SHA_LONG32
 *
 * result into s
 *
 */

SHA_LONG32 * snor32_64( SHA_LONG32 *s, SHA_LONG32 *l, SHA_LONG32 *r )
{
  s->i[0] = l->i[0] ^ r->i[0];
  s->i[1] = l->i[1] ^ r->i[1];

  return s;
}



# ifndef PULL64


extern void ui32to64( unsigned int ui, SHA_LONG32 *p );
extern void shift_left( SHA_LONG32 *p, unsigned int n);
extern void shift_right( SHA_LONG32 *p, unsigned int n);
void or32_64( SHA_LONG32 *l, SHA_LONG32 *r );


/*
 * #  define B(x,j)    (((SHA_LONG64)(*(((const unsigned char *)(&x))+j)))<<((7-j)*8))
 */

SHA_LONG32 * B( SHA_LONG32 *x, int j )
{
  const unsigned char *p = (unsigned char *) x;
  unsigned int ch;

  ch = (unsigned int) *( p + j );
  ui32to64( ch, x );
  shift_left( x, (7-j)*8 );  

  return x;
}

/*
 * #  define PULL64(x) (B(x,0)|B(x,1)|B(x,2)|B(x,3)|B(x,4)|B(x,5)|B(x,6)|B(x,7))
 */

SHA_LONG32 * PULL64( SHA_LONG32 *x )
{
  /* need to  keep intermediate values */
  SHA_LONG32 tmp[8];
  int i;
 
  for( i=0; i<8; i++)
    {
      tmp[i].i[0] = x->i[0];
      tmp[i].i[1] = x->i[1];

      B( &tmp[i], i );             /* make B( x, 0 ... 7 ) */
      /* Make
       * B(x,0)|B(x,1)|B(x,2)|B(x,3)|B(x,4)|B(x,5)|B(x,6)|B(x,7)
       * if tmp[0] | tmp[0] always will be tmp[0]
       * tmp[0] will accumulates all operations or
       */
      or32_64( &tmp[0], &tmp[i] );
    }
  x->i[0] = tmp[0].i[0];
  x->i[1] = tmp[0].i[1];

  return x;
}

# endif


# ifndef ROTR

/* #  define ROTR(x,s)  (((x)>>s) | (x)<<(64-s)) */

SHA_LONG32 * ROTR( SHA_LONG32 *x, int s )
{
  SHA_LONG32 tmp1, tmp2;

  tmp1.i[0] = tmp2.i[0] = x->i[0];
  tmp1.i[1] = tmp2.i[1] = x->i[1];

  shift_right( &tmp1, s );
  shift_left( &tmp2, 64-s );  
  
  return sor32_64( x, &tmp1, &tmp2 );
}

# endif

/* # define Sigma0(x)       (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39)) */

SHA_LONG32 * Sigma0( SHA_LONG32 *x )
{
  SHA_LONG32 tmp1, tmp2, tmp3;

  tmp1.i[0] = tmp2.i[0] = tmp3.i[0] = x->i[0];
  tmp1.i[1] = tmp2.i[1] = tmp3.i[1] = x->i[1];

  ROTR( &tmp1, 28 );
  ROTR( &tmp2, 34 );
  ROTR( &tmp3, 39 );

  return snor32_64( x, &tmp1, snor32_64( &tmp2, &tmp2, &tmp3 ) );
}

/* # define Sigma1(x)       (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41)) */

SHA_LONG32 * Sigma1( SHA_LONG32 *x )
{
  SHA_LONG32 tmp1, tmp2, tmp3;

  tmp1.i[0] = tmp2.i[0] = tmp3.i[0] = x->i[0];
  tmp1.i[1] = tmp2.i[1] = tmp3.i[1] = x->i[1];

  ROTR( &tmp1, 14 );
  ROTR( &tmp2, 18 );
  ROTR( &tmp3, 41 );

  return snor32_64( x, &tmp1, snor32_64( &tmp2, &tmp2, &tmp3 ) );
}

/* # define sigma0(x)       (ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7)) */

SHA_LONG32 * sigma0( SHA_LONG32 *x )
{
  SHA_LONG32 tmp1, tmp2, tmp3;

  tmp1.i[0] = tmp2.i[0] = tmp3.i[0] = x->i[0];
  tmp1.i[1] = tmp2.i[1] = tmp3.i[1] = x->i[1];

  ROTR( &tmp1, 1 );
  ROTR( &tmp2, 8 );
  shift_left( &tmp3, 7 );

  return snor32_64( x, &tmp1, snor32_64( &tmp2, &tmp2, &tmp3 ) );
}

/* # define sigma1(x)       (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6)) */

SHA_LONG32 * sigma1( SHA_LONG32 *x )
{
  SHA_LONG32 tmp1, tmp2, tmp3;

  tmp1.i[0] = tmp2.i[0] = tmp3.i[0] = x->i[0];
  tmp1.i[1] = tmp2.i[1] = tmp3.i[1] = x->i[1];

  ROTR( &tmp1, 19 );
  ROTR( &tmp2, 61 );
  shift_left( &tmp3, 6 );

  return snor32_64( x, &tmp1, snor32_64( &tmp2, &tmp2, &tmp3 ) );
}

/* # define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z))) */

SHA_LONG32 * Ch( SHA_LONG32 *x, SHA_LONG32 *y, SHA_LONG32 *z )
{
  SHA_LONG32 tmpx1, tmpx2, tmpy, tmpz;
  
  tmpx1.i[0] = tmpx2.i[0] = x->i[0];
  tmpx1.i[1] = tmpx2.i[1] = x->i[1];

  tmpy.i[0] = y->i[0];
  tmpy.i[1] = y->i[1];

  tmpz.i[0] = z->i[0];
  tmpz.i[1] = z->i[1];

  tmpx2.i[0] = ~tmpx2.i[0];
  tmpx2.i[1] = ~tmpx2.i[1];

  sand32_64( &tmpx1, &tmpx1, &tmpy );  /* tmpx1 = ((x) & (y))     */
  sand32_64( &tmpx2, &tmpx2, &tmpz );  /* tmpx2 = ((~(x)) & (z))  */

  return snor32_64( x, &tmpx1, &tmpx2 );
}



/* # define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) */

SHA_LONG32 * Maj( SHA_LONG32 *x, SHA_LONG32 *y, SHA_LONG32 *z )
{
  SHA_LONG32 tmpx1, tmpx2, tmpy, tmpz;

  tmpx1.i[0] = tmpx2.i[0] = x->i[0];
  tmpx1.i[1] = tmpx2.i[1] = x->i[1];

  tmpy.i[0] = y->i[0];
  tmpy.i[1] = y->i[1];

  tmpz.i[0] = tmpz.i[0] = z->i[0];
  tmpz.i[1] = tmpz.i[1] = z->i[1];

  sand32_64( &tmpx1, &tmpx1, &tmpy );  /* tmpx1 = ((x) & (y)) */
  sand32_64( &tmpx2, &tmpx2, &tmpz );  /* tmpx2 = ((x) & (z)) */
  sand32_64( &tmpy,  &tmpy,  &tmpz );  /* tmpy  = ((y) & (z)) */

  return snor32_64( x, &tmpx1, snor32_64( &tmpx2, &tmpx2, &tmpy ) );
}


/*
 *=========================================================================
 * Work here ...
 *=========================================================================
 *
 */


/*
 * This code should give better results on 32-bit CPU with less than
 * ~24 registers, both size and performance wise...
 */


/*
static void sha512_block_data_order(SHA512_CTX *ctx, const void *in,
                                    size_t num)
{
    const SHA_LONG64 *W = in;
    SHA_LONG64 A, E, T;
    SHA_LONG64 X[9 + 80], *F;
    int i;

    while (num--) {

        F = X + 80;
        A = ctx->h[0];
        F[1] = ctx->h[1];
        F[2] = ctx->h[2];
        F[3] = ctx->h[3];
        E = ctx->h[4];
        F[5] = ctx->h[5];
        F[6] = ctx->h[6];
        F[7] = ctx->h[7];

        for (i = 0; i < 16; i++, F--) {
#  ifdef B_ENDIAN
            T = W[i];
#  else
            T = PULL64(W[i]);
#  endif
            F[0] = A;
            F[4] = E;
            F[8] = T;
            T += F[7] + Sigma1(E) + Ch(E, F[5], F[6]) + K512[i];
            E = F[3] + T;
            A = T + Sigma0(A) + Maj(A, F[1], F[2]);
        }

        for (; i < 80; i++, F--) {
            T = sigma0(F[8 + 16 - 1]);
            T += sigma1(F[8 + 16 - 14]);
            T += F[8 + 16] + F[8 + 16 - 9];

            F[0] = A;
            F[4] = E;
            F[8] = T;
            T += F[7] + Sigma1(E) + Ch(E, F[5], F[6]) + K512[i];
            E = F[3] + T;
            A = T + Sigma0(A) + Maj(A, F[1], F[2]);
        }

        ctx->h[0] += A;
        ctx->h[1] += F[1];
        ctx->h[2] += F[2];
        ctx->h[3] += F[3];
        ctx->h[4] += E;
        ctx->h[5] += F[5];
        ctx->h[6] += F[6];
        ctx->h[7] += F[7];

        W += SHA_LBLOCK;
    }
}
*/

/*===================================================================*/