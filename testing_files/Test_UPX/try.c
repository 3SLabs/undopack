#include<stdio.h>

void func()
{
	printf("In function\n");
	return ;
}

int main()
{
	printf("In mains\n");
	func();
	return 0;
}
