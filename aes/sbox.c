#include<stdio.h>
#define ROTL(x,shift) ( ((x) << shift) | ((x) >> (8 - shift)))
void main()
{
	unsigned char p,q,result;
	unsigned char sbox[256];
	p=1;q=1;
	do{
		/*multiply p by 2*/
		p = p ^ (p <<1) ^ (p  & 0x80 ? 0x1b:0);
		printf("p:%d q:%d hexq:%x ",p,q,q);
		/*divide by2*/
		q ^= q <<1;
		q ^= q <<2;
		q ^= q <<4;
		q ^= q & 0x80 ? 0x09 : 0;
		printf(" Q:%d q:%x ",q,q);
		result = q ^ ROTL(q,1) ^ ROTL(q,2) ^ ROTL(q,3) ^ ROTL(q,4);
		sbox[p] = result ^ 0x63;
		printf(" result:%x sbox:%x p:%x\n",result,sbox[p],p);
	}
	while(p!=1);
	sbox[0] = 0x63;
}
