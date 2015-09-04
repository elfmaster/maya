#include <stdio.h>
#include <stdlib.h>

int func(void)
{
	printf("Child starts\n");
	return 0;
}

int main(int argc, char **argv)
{
	int pid, status;
	pid = fork();
	if (pid == 0) {
		func();
	}
	wait(&status);
	if (WIFEXITED(status))
		printf("child ends\n"); 

	printf("Parent ends\n");
	exit(0);
}
