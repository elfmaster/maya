#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

void func3(void)
{
	printf("Three!\n");
}

void func2(void)
{
	printf("Two!\n");
}

void func1(void)
{
	int fd = open("/tmp/fuckit.0", O_RDONLY);
	printf("One!\n");
	close(fd);
}

int main(void)
{
	int i;
	for (i = 0; i < 10; i++) {
	func1();
	func2();
	func3();
	}
	exit(0);
}
	
	
