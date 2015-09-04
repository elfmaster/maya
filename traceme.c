#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>

int check_serial(char *s)
{
	char serial[] = {'L', 'e', 'V', 'i', 'a', 't', 'h', 'a', 'n', '3', '1', '\0'};
	char *p;

	if ((p = strchr(s, '\n')) != NULL)
		*p = '\0';
	
	if (!strcmp(serial, s))
		return 1;
	return 0;
}

int dummy_check(char *s)
{
	printf("Checking serial...\n");
	sleep(2);
	int r = check_serial(s);
	return r;
}

int main(void)
{
	char c;
	int j;
	char buf[256];
	char *p = (char *)&check_serial;
	for (j = 0; j < 175; j++)
		if (p[j] == 0x90)
			printf("... you fucked up ...\n");
	for (;;) {
		printf("Enter serial number: ");
		fgets(buf, sizeof(buf), stdin);
		if (dummy_check(buf) == 1) {
			printf("Congratulations, you have a licensed copy of ./traceme\n");
			exit(0);
		}
		continue;
	}
}


