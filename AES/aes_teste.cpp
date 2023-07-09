#include "aes.h"
#include <stdio.h>


/*
Casos de teste: 
https://developers.google.com/nearby/fast-pair/specifications/appendix/testcases
*/
int main(){
  
  int i;
  uint8_t key[] = {0xA0, 0xBA, 0xF0, 0xBB, 0x95, 0x1F, 0xF7, 0xB6, 0xCF, 0x5E, 0x3F, 0x45, 0x61, 0xC3, 0x32, 0x1D};
  uint8_t msg[] = {0xF3, 0x0F, 0x4E, 0x78, 0x6C, 0x59, 0xA7, 0xBB, 0xF3, 0x87, 0x3B, 0x5A, 0x49, 0xBA, 0x97, 0xEA};
  uint8_t enc[] = {0xAC, 0x9A, 0x16, 0xF0, 0x95, 0x3A, 0x3F, 0x22, 0x3D, 0xD1, 0x0C, 0xF5, 0x36, 0xE0, 0x9E, 0x9C};
  uint8_t buf[16];

  AES128 aes(key);

  /* verifica se a cifragem funciona */
  aes.encrypt_block(msg, buf);

  for (i=0;i<16;i++) 
    if (buf[i] != enc[i]) {
      printf("AES Encryption Fail!\n");
      return 1;
    }

  /* verifica se a decifragem funciona */
  aes.decrypt_block(enc, buf);

  for (i=0;i<16;i++)
    if (buf[i] != msg[i]) {
      printf("AES Decryption Fail!\n");
      return 1;
    }
  return 0;
}