/* 
   Red Pike 2 cipher source code 
   By Alexander Pukall 2015 
   
   128-bit block cipher (like AES) 128-bit key
   
   Code free for all even for commercial applications 
   
   Based on Alleged Red Pike by GCHQ
   
   Compile with gcc : gcc redpike2.c -o redpike2
   
*/

#include <stdint.h>
#include <stdio.h>

typedef uint64_t word;

#define CONST 0xFD258F8F3210C68 /* sqr(5)-1 * 2^63 */
#define ROUNDS 64

#define ROTL(X, R) (((X) << ((R) & 63)) | ((X) >> (64 - ((R) & 63))))
#define ROTR(X, R) (((X) >> ((R) & 63)) | ((X) << (64 - ((R) & 63))))

void encrypt(word * x,  word * k)
{
  unsigned int i;
  word rk0 = k[0];
  word rk1 = k[1];

  for (i = 0; i < ROUNDS; i++)
  {
   rk0 += CONST;
   rk1 -= CONST;
 
    x[0] ^= rk0;
    x[0] += x[1];
    x[0] = ROTL(x[0], x[1]);

    x[1] = ROTR(x[1], x[0]);
    x[1] -= x[0];
    x[1] ^= rk1;
  }

  rk0 = x[0]; x[0] = x[1]; x[1] = rk0;
}

void decrypt(word * x, word * k)
{
  word sum;
  sum=0x4689735BB642668;  /* (CONST * (ROUNDS + 1)) & 0xFFFFFFFFFFFFFFFF  */
   
  word dk[2] =
  {
    k[1] - sum,
    k[0] + sum
  };

  encrypt(x, dk);
}

void main()
{
  word x[2];
  word k[2];
  
  /* 128-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  x[0]=0x0000000000000000;
  x[1]=0x0000000000000000;
 
  printf("Red Pike 2 by Alexander PUKALL 2015 \n 128-bit block 128-bit key\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on Alleged Red Pike by GCHQ\n\n");
  
  printf("Encryption 1\n");
  
  printf("Key:       %0.16llX %0.16llX \n",k[0],k[1]);
   
  printf("Plaintext: %0.16llX %0.16llX\n",x[0],x[1]);
  
  encrypt(x,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",x[0],x[1]);
  

  decrypt(x,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",x[0],x[1]);
  
  /* 128-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  x[0]=0x0000000000000000;
  x[1]=0x0000000000000001;
  
  printf("Encryption 2\n");
  

  printf("Key:       %0.16llX %0.16llX \n",k[0],k[1]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",x[0],x[1]);
  
  encrypt(x,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",x[0],x[1]);
  
  decrypt(x,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",x[0],x[1]);
  
  /* 128-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  x[0]=0x0000000000000001;
  x[1]=0x0000000000000001;
  
  printf("Encryption 3\n");
  
  printf("Key:       %0.16llX %0.16llX \n",k[0],k[1]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",x[0],x[1]);
  
  encrypt(x,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",x[0],x[1]);
  
  decrypt(x,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",x[0],x[1]);
  
   
}

/*
 Encryption 1
Key:       0000000000000000 0000000000000001 
Plaintext: 0000000000000000 0000000000000000
Ciphertext:4F44F345CDA11C28 91467EBA093AAE8E
Decrypted: 0000000000000000 0000000000000000

Encryption 2
Key:       0000000000000000 0000000000000001 
Plaintext: 0000000000000000 0000000000000001
Ciphertext:0820B8CC89A26EA1 562F7DBC9BCAB3FB
Decrypted: 0000000000000000 0000000000000001

Encryption 3
Key:       0000000000000000 0000000000000001 
Plaintext: 0000000000000001 0000000000000001
Ciphertext:D76A189F0E4797B5 7AD5260C74D00D31
Decrypted: 0000000000000001 0000000000000001

*/
  
  
