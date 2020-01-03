#include <stdio.h>
#include "sha_test.h"

extern unsigned int *K512_32[];
extern SHA_LONG64 *K512[];


typedef union {
  unsigned long long l;
  unsigned int   i[2];
  } _u;

/*
 *===============================================================
 *===============================================================
 *
 */

extern void add_uu( SHA_LONG32 *, SHA_LONG32 * );
extern SHA_LONG32 * sum_uu( SHA_LONG32 *, SHA_LONG32 *, SHA_LONG32 * );
extern void shift_left( SHA_LONG32 *, unsigned int );
extern void shift_right( SHA_LONG32 *, unsigned int );
extern void plus_plus( SHA_LONG32 * );
extern void minus_minus( SHA_LONG32 * );
extern void ne32_64( SHA_LONG32 * );

extern void get_K512_32( SHA_LONG32 *value, unsigned int cnt );
extern void get_K512( unsigned long long *value, unsigned int cnt );

/*------------------------------------------------------------------
 *  Print test defines
 *-----------------------------------------------------------------*/

/*========================================================*/
/* It is a test all functions, which will replace defines */

#  define B(x,j)    (((SHA_LONG64)(*(((const unsigned char *)(&x))+j)))<<((7-j)*8))
#  define PULL64(x) (B(x,0)|B(x,1)|B(x,2)|B(x,3)|B(x,4)|B(x,5)|B(x,6)|B(x,7))

#  define ROTR(x,s)  (((x)>>s) | (x)<<(64-s))

# define Sigma0(x)       (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
# define Sigma1(x)       (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))

# define sigma0(x)       (ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7))
# define sigma1(x)       (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))

# define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
# define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

extern SHA_LONG32 * B_32( SHA_LONG32 *, int );
extern SHA_LONG32 * PULL64_32( SHA_LONG32 * );
extern SHA_LONG32 * ROTR_32( SHA_LONG32 *, int );
extern SHA_LONG32 * Sigma0_32( SHA_LONG32 * );
extern SHA_LONG32 * Sigma1_32( SHA_LONG32 * );
extern SHA_LONG32 * sigma0_32( SHA_LONG32 * );
extern SHA_LONG32 * sigma1_32( SHA_LONG32 * );
extern SHA_LONG32 * Ch_32( SHA_LONG32 *, SHA_LONG32 *, SHA_LONG32 * );
extern SHA_LONG32 * Maj_32( SHA_LONG32 *, SHA_LONG32 *, SHA_LONG32 * );

void print_test_defines( )
{
    SHA_LONG64 In, Inx, Iny, Inz;
    SHA_LONG32 in, inx, iny, inz;
    SHA_LONG64 T;
    SHA_LONG32 t;
    SHA_LONG32 *pt;


    printf("-> Test DEFINES and them FUNCTION to replace to...\n\n");

/*
 * #  define B(x,j)    (((SHA_LONG64)(*(((const unsigned char *)(&x))+j)))<<((7-j)*8))
 *
 * #  define PULL64(x) (B(x,0)|B(x,1)|B(x,2)|B(x,3)|B(x,4)|B(x,5)|B(x,6)|B(x,7))
 */

   In = in.l = 0x6a09e667f3bcc908;                             /* initialize value for the test */
   
   T = PULL64( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = PULL64_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function PULL64_32 vs define PULL64.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function PULL64_32 isn't OK.\n"); }

   In = in.l = 0x0123456789abcdef;                             /* initialize value for the test */
   
   T = PULL64( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = PULL64_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function PULL64_32 vs define PULL64.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function PULL64_32 isn't OK.\n"); }

   In = in.l = 0xfedcba9876543210;                             /* initialize value for the test */
   
   T = PULL64( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = PULL64_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function PULL64_32 vs define PULL64.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function PULL64_32 isn't OK.\n"); }

/* # define Sigma0(x)       (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
 *
 *   SHA_LONG32 * Sigma0_32( SHA_LONG32 *x )
 */

   In = in.l = 0x6a09e667f3bcc908;                             /* initialize value for the test */
   
   T = Sigma0( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = Sigma0_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Sigma0_32 vs define Sigma0.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Sigma0_32 isn't OK.\n"); }

   In = in.l = 0x0123456789abcdef;                             /* initialize value for the test */
   
   T = Sigma0( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = Sigma0_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Sigma0_32 vs define Sigma0.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Sigma0_32 isn't OK.\n"); }

   In = in.l = 0xfedcba9876543210;                             /* initialize value for the test */
   
   T = Sigma0( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = Sigma0_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Sigma0_32 vs define Sigma0.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Sigma0_32 isn't OK.\n"); }


/* # define Sigma1(x)       (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
 *
 * SHA_LONG32 * Sigma1_32( SHA_LONG32 *x )
 */

   In = in.l = 0x6a09e667f3bcc908;                             /* initialize value for the test */
   
   T = Sigma1( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = Sigma1_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Sigma1_32 vs define Sigma1.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Sigma1_32 isn't OK.\n"); }

   In = in.l = 0x0123456789abcdef;                             /* initialize value for the test */
   
   T = Sigma1( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = Sigma1_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Sigma1_32 vs define Sigma1.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Sigma1_32 isn't OK.\n"); }

   In = in.l = 0xfedcba9876543210;                             /* initialize value for the test */
   
   T = Sigma1( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = Sigma1_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Sigma1_32 vs define Sigma1.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Sigma1_32 isn't OK.\n"); }


/* # define sigma0(x)       (ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7))
 *
 *  SHA_LONG32 * sigma0_32( SHA_LONG32 *x )
 */

   In = in.l = 0x6a09e667f3bcc908;                             /* initialize value for the test */
   
   T = sigma0( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = sigma0_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function sigma0_32 vs define sigma0.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function sigma0_32 isn't OK.\n"); }

   In = in.l = 0x0123456789abcdef;                             /* initialize value for the test */
   
   T = sigma0( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = sigma0_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function sigma0_32 vs define sigma0.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function sigma0_32 isn't OK.\n"); }

   In = in.l = 0xfedcba9876543210;                             /* initialize value for the test */
   
   T = sigma0( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = sigma0_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function sigma0_32 vs define sigma0.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function sigma0_32 isn't OK.\n"); }


/* # define sigma1(x)       (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))
 *
 *  SHA_LONG32 * sigma1_32( SHA_LONG32 *x )
 */

   In = in.l = 0x6a09e667f3bcc908;                             /* initialize value for the test */
   
   T = sigma1( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = sigma1_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function sigma1_32 vs define sigma1.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function sigma1_32 isn't OK.\n"); }

   In = in.l = 0x0123456789abcdef;                             /* initialize value for the test */
   
   T = sigma1( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = sigma1_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function sigma1_32 vs define sigma1.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function sigma1_32 isn't OK.\n"); }

   In = in.l = 0xfedcba9876543210;                             /* initialize value for the test */
   
   T = sigma1( In );
   t.i[0] = in.i[0];                                           /* need to save variable */
   t.i[1] = in.i[1];
   pt = sigma1_32( &t );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function sigma1_32 vs define sigma1.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function sigma1_32 isn't OK.\n"); }


/* # define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
 *
 *  SHA_LONG32 * Ch_32( SHA_LONG32 *x, SHA_LONG32 *y, SHA_LONG32 *z )
 */

   Inx = inx.l = 0x0123456789abcdef;
   Iny = iny.l = 0xfedcba9876543210;
   Inz = inz.l = 0xa5a5a5a5a5a5a5a5;

   T = Ch( Inx, Iny, Inz );
   t.i[0] = inx.i[0];                                          /* need to save variable */
   t.i[1] = inx.i[1];
   pt = Ch_32( &t, &iny, &inz );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Ch_32 vs define Ch.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Ch_32 isn't OK.\n"); }
      

/* # define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
 *
 * SHA_LONG32 * Maj_32( SHA_LONG32 *x, SHA_LONG32 *y, SHA_LONG32 *z )
 *
 */

   Inx = inx.l = 0x5a5a5a5a5a5a5a5a;
   Iny = iny.l = 0xfedcba9876543210;
   Inz = inz.l = 0x1234567898765432;

   T = Maj( Inx, Iny, Inz );
   t.i[0] = inx.i[0];                                          /* need to save variable */
   t.i[1] = inx.i[1];
   pt = Maj_32( &t, &iny, &inz );

   if( pt == &t )                                              /* check value of pointer */
     {
        printf("-> it's function Maj_32 vs define Maj.\n");
        printf("[%016llX] == [%08X.%08X]\n", T, t.i[1], t.i[0]);
        printf("[%016llX] == [%016llX]\n", T, t.l);
     }
   else
     { printf("-> function Maj_32 isn't OK.\n"); }



}     /* End of print_test_defines */


/*------------------------------------------------------------------
 *  Main
 *-----------------------------------------------------------------*/
int main()
{ 
  unsigned long long ull, ull1, us;

  SHA512_CTX    sha512;
  SHA512_32CTX  sha512_32;

  SHA_LONG32 s, u, u1, tmp;

  unsigned int i, j, k;

  printf("Size sha512 is [%u], size sha512_32 is [%u]\n\n",
          sizeof(sha512), sizeof(sha512_32));
  
  printf("Size sha512->u is [%u], size sha512_32->u is [%u]\n\n",
          sizeof(sha512.u), sizeof(sha512_32.u));

  printf("Size u->l is [%u], size u->i is [%u], size u->i[0] is [%u]\n\n",
          sizeof(u.l), sizeof(u.i), sizeof(u.i[0]));

  printf("Size long long is [%u]\n\n", sizeof(ull));


  sha512_32.h[0].i[1] = sha512_32.h[0].i[0] = 0;

  u.l   = 0x6a09e667f3bcc908;
  u1.l  = 0x123456789abcdef0;

  ull   = 0x6a09e667f3bcc908;
  ull1  = 0x123456789abcdef0;

  us = s.l = 0;

  printf("Beginning with:\nL [%016llx], I [%08x.%08x]\nL [%016llx], I [%08x.%08x], [%016llx]\n\n\n",
           ull, u.i[1], u.i[0], us, s.i[1], s.i[0], s.l );

  for ( i=0; i <10 ; i++)
   {
    ull += ull1;
    add_uu( &u, &u1 );

    us = ull + ull1;
    sum_uu( &s, &u, &u1 );
    printf("L [%016llx], I [%08x.%08x]\nL [%016llx], I [%08x.%08x], [%016llx]\n\n",
           ull, u.i[1], u.i[0], us, s.i[1], s.i[0], s.l );
   }

  printf("\n\n========================================\n\n");

  for( i=0; i<80; i++ )
   {
     get_K512_32( &tmp, i );
    
     get_K512( &ull, i );
     
     if( ull == tmp.l )
        {
          printf("{%2d} - Ok ", i);
          if( !((i+1)%4) )
              printf("\n");
        }
     else
         printf("{%2d} L [%016llx], I [%08x.%08x], [%016llx]\n",
                 i, ull, tmp.i[1], tmp.i[0], tmp.l );
   }
  printf("\n");

  /* Check shift_left & shift_right */
  
  for(i=0; i<64; i++)
      {
        tmp.l = 0x0000000000000001;
        shift_left( &tmp, i );
        printf("[%2d] -> [%016llx] == [%08x.%08x]\n", i, tmp.l, tmp.i[1], tmp.i[0]);
      }

  printf("\n\n==================================\n\n");

  for(i=0; i<64; i++)
      {
        tmp.l = 0x8000000000000000;
        shift_right( &tmp, i );
        printf("[%2d] -> [%016llx] == [%08x.%08x]\n", i, tmp.l, tmp.i[1], tmp.i[0]);
      } 

  k=0;
  tmp.l = 0xfffffff0;
  ull   = 0xfffffff0;

  /* Check plus_plus & minus_minus */

  printf("\n=== Test ++ ====================================\n\n");

  printf("[%016llX] == [%08X.%08X]\n", ull, tmp.i[1], tmp.i[0]);
  for(j=0; j<32; j++)
      {
        ull++;
        plus_plus( &tmp );
        printf("[%016llX] == [%08X.%08X]\n", ull, tmp.i[1], tmp.i[0]);
      }

  printf("\n== Test -- =====================================\n\n");

  printf("[%016llX] == [%08X.%08X]\n", ull, tmp.i[1], tmp.i[0]);
  for(j=0; j<32; j++)
      {
        ull--;
        minus_minus( &tmp );
        printf("[%016llX] == [%08X.%08X]\n", ull, tmp.i[1], tmp.i[0]);
      }

  printf("\n== Test ~ =====================================\n\n");
  
  tmp.l = 0x55555555;
  printf("[%016llX] == [%08X.%08X]\n", tmp.l, tmp.i[1], tmp.i[0]);
  
  ne32_64( &tmp );

  printf("[%016llX] == [%08X.%08X]\n", tmp.l, tmp.i[1], tmp.i[0]);

  printf("============================================\n");

  print_test_defines();


  printf("That is ALL.\n\n");

}

/*
 *
 *
 */