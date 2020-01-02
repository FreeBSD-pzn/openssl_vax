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
extern void print_test_defines();

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