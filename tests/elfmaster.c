#include <stdio.h>

void print_string(char *p)
{
	static int i = 0;

	printf("[count %d] The string \"%s\" is now resident on the heap at %p\n", ++i, p, p);
}

char *malloc_string(char *s)
{
	char *p;
	p = malloc(strlen(s) + 1);
	strcpy(p, s);
	return p;
}

void exit_banner(char *string)
{
	printf("*** %s ***\n", string);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("Usage: %s <#_of_loops>\n", argv[0]);
		exit(0);
	}
	char *p;
	int i;
	int count = atoi(argv[1]);
	for (i = 0; i < count; i++)
	{
		p = malloc_string("This string is stored in .rodata!\n");
		print_string(p);
	}
	
	//exit_banner("Have a wonderful day!\n");
	//exit(0);
}

