#include <stdio.h>
#include <string.h>
#include "api.h"

unsigned char storage[64] = {0x0};
unsigned char msg[] = "abc";
unsigned char sha256Out[32], sha256Out2[32];

void printArrAscii(unsigned char *input, unsigned int len)
{
  int i;
  for (i = 1; i <= len; i++)
    {
      printf("%c ", input[i]);
      if ((i % 16 == 0) && (i != 1))
	{
	  printf("\n");
	}
    }
  printf("\n");
}
void printArrHex(unsigned char *input, unsigned int len)
{
  int i;
  for (i = 0; i < len; i++)
    {
      printf("%02x ", input[i]);
      if (((i + 1) % 16 == 0) && (i != 0))
	{
	  printf("\n");
	}
    }
  printf("\n");
}

int main()
{
  printf("Hello secp256k1\n");
  printf("go\n");

  if (quick_test(storage, strlen((const char *)storage)) == 0)
    {
      printf("\nquick test Succeed!\n");
      printArrHex(storage, sizeof(storage));
    }

  printf("\nTo test sha256:\n");
  printf("msg: %s\n", msg);
  printf("msg len: %lu\n", strlen((const char *)msg));

  if (quick_sha256(msg, strlen((const char *)msg), sha256Out) == 0)
    {
      printf("sha256 1st finished\n");
      printArrHex(sha256Out, 32);
    }
  if (quick_sha256(sha256Out, 32, sha256Out2) == 0)
    {
      printf("sha256 2nd finished\n");
      printArrHex(sha256Out2, 32);
    }
  
  printf("\nTo test sign:\n");
  
  return 0;
}
