#include<stdio.h>
#include "aes.h"

void main(int argc, char **argv)
{
	int i;
	unsigned char input[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};

	for(i=0;i<16;i++)
		printf("%x ",input[i]);
	
	aesEncrypt(input);
}
