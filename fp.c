#include "maya.h"

int generate_fingerprint(uint8_t *fingerprint)
{
	int fd, i;
	uint8_t mem[FINGERPRINT_SIZE];
	uint8_t *bp = fingerprint;

	if ((fd = open("/proc/iomem", O_RDONLY)) < 0) {
		fprintf(stderr, "[!] Unable to open /proc/iomem for reading\n");
		return -1;
	}

	read(fd, mem, FINGERPRINT_SIZE);

	for (i = 0; i < FINGERPRINT_SIZE; i ++) {
		*(fingerprint++) = mem[i];
	}
	return 0;
}
	


