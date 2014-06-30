#include<stdio.h>

int main()
{
	char a = 0x11;
	printf("a>>1 = %x\n",(a>>1)&1);
	return 0;
}
