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

#define CONST 0x9E3779B97F4A7C15
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
  sum=0x2C15E81951E98155;  /* (CONST * (ROUNDS + 1)) & 0xFFFFFFFFFFFFFFFF  */
   
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
Ciphertext:CC01C3290E9CC34F 2B80C148D5B5F9B8
Decrypted: 0000000000000000 0000000000000000

Encryption 2
Key:       0000000000000000 0000000000000001 
Plaintext: 0000000000000000 0000000000000001
Ciphertext:12C989B272EBB55F A06A1D66DFA1690B
Decrypted: 0000000000000000 0000000000000001

Encryption 3
Key:       0000000000000000 0000000000000001 
Plaintext: 0000000000000001 0000000000000001
Ciphertext:213A3125CA8BC8E6 DF979478C536344C
Decrypted: 0000000000000001 0000000000000001

*/
