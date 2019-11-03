#include <stdio.h>
#include "sha_test.h"

extern unsigned int *K512_32[];
extern SHA_LONG64 *K512[];


typedef union {
  unsigned long long l;
  unsigned int   i[2];
  } _u;

/* Analog v = +p 64 bit operation 
 * where u[1] - high 32 bit u[0] - low 32 bit
 *
 *
 *
 */
void add_uu( SHA_LONG32 *v, SHA_LONG32 *p )
{
  unsigned int tmp, tmp1;
 
  tmp  = v->i[0];
  tmp1 = p->i[0];

  /* Keep high bit low 32 bit sum, to add it to the high 32 bit*/
  tmp  = tmp  >> 1;
  tmp1 = tmp1 >> 1;
  tmp  += tmp1;
  tmp  = tmp >> 31;

  v->i[1] += p->i[1];
  v->i[1] += tmp;

  v->i[0] += p->i[0];
}


/* Analog s = a + b 64 bit operation 
 * where s[1] - high 32 bit s[0] - low 32 bit
 *
 *
 *
 */
SHA_LONG32 * sum_uu( SHA_LONG32 *s, SHA_LONG32 *a, SHA_LONG32 *b )
{
  unsigned int tmp, tmp1;
 
  tmp  = a->i[0];
  tmp1 = b->i[0];

  /* Keep high bit low 32 bit sum, to add it to the high 32 bit*/
  tmp  = tmp  >> 1;
  tmp1 = tmp1 >> 1;
  tmp  += tmp1;
  tmp  = tmp >> 31;

  s->i[1] = a->i[1] + b->i[1];
  s->i[1] += tmp;

  s->i[0] = a->i[0] + b->i[0];

  return s;
}


/* Analog p = p << n  64 bit operation 
 * where p[1] - high 32 bit p[0] - low 32 bit
 *
 *
 *
 */
void shift_left( SHA_LONG32 *p, unsigned int n)
{
  unsigned int tmp;

  if( n > 0 )
     {
       if( n < 32 )
          {
            tmp = p->i[0];
            p->i[0] = p->i[0]<<n;
            p->i[1] = p->i[1]<<n;
            tmp = tmp >> (32-n);
            p->i[1] |= tmp;
          }  
       else
          { 
            p->i[1] = p->i[0];
            p->i[0] = 0;
            p->i[1] = p->i[1]<<(n-32);
          }
     }
}


/* Analog p = p >> n  64 bit operation 
 * where p[1] - high 32 bit p[0] - low 32 bit
 *
 *
 *
 */
void shift_right( SHA_LONG32 *p, unsigned int n)
{
  unsigned int tmp;

  if( n > 0 )
     {
       if( n < 32 )
          {
           tmp = p->i[1];
           p->i[0] = p->i[0]>>n;
           p->i[1] = p->i[1]>>n;
           tmp = tmp << (32-n);
           p->i[0] |= tmp;
          }
       else
          {
            p->i[0] = p->i[1];
            p->i[1] = 0;
            p->i[0] = p->i[0]>>(n-32);
          }
     }
}


/* Analog p++  64 bit operation 
 * where p[1] - high 32 bit p[0] - low 32 bit
 *
 *
 *
 */
void plus_plus( SHA_LONG32 *p )
{
  if( p->i[0] < 0xffffffff )
      p->i[0]++;
  else
     {
      p->i[0] = 0;
      p->i[1]++;
     }
}


/* Analog p--  64 bit operation 
 * where p[1] - high 32 bit p[0] - low 32 bit
 *
 *
 *
 */
void minus_minus( SHA_LONG32 *p )
{
  if( p->i[0] > 0 )
      p->i[0]--;
  else
     {
       p->i[0] = 0xffffffff;
       p->i[1]--;
     }
}


/* Analog convert 32 unsigned bit -> 64 unsigned bit
 *  ull = (unsigned long long) ui;
 *
 * where ui - unsigned int
 *       *p - unsigned int [2]
 *
 */
void ui32to64( unsigned int ui, SHA_LONG32 *p )
{
  p->i[0] = ui;
  p->i[1] = 0x0;
}


/* Analog logical OR - |
 * l |= r
 *
 * where l - SHA_LONG32
 *       r - SHA_LONG32
 *
 * result into l
 *
 */

void or32_64( SHA_LONG32 *l, SHA_LONG32 *r )
{
  l->i[0] |= r->i[0];
  l->i[1] |= r->i[1];
}


/* Analog logical AND - & 
 * l &= r
 * 
 * where l - SHA_LONG32
 *       r - SHA_LONG32
 *
 * result into l
 *
 */

void and32_64( SHA_LONG32 *l, SHA_LONG32 *r )
{
  l->i[0] &= r->i[0];
  l->i[1] &= r->i[1];
}


/* Analog logical ORNE ^ 
 * l ^= r
 * 
 * where l - SHA_LONG32
 *       r - SHA_LONG32
 *
 * result into l
 *
 */

void orne32_64( SHA_LONG32 *l, SHA_LONG32 *r )
{
  l->i[0] ^= r->i[0];
  l->i[1] ^= r->i[1];
}

/* Analog logical NE ~ 
 * ~p
 * 
 * where p - SHA_LONG32
 *
 *
 */

void ne32_64( SHA_LONG32 *p )
{
  p->i[0] =~p->i[0];
  p->i[1] =~p->i[1];
}




/*
 *===============================================================
 *===============================================================
 *
 */



extern void get_K512_32( SHA_LONG32 *value, unsigned int cnt );
extern void get_K512( unsigned long long *value, unsigned int cnt );

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



  printf("That is ALL.\n\n");

}

/*
 *
 *
 */