#include "maya.h"

/*
 * Flexible crypto functionality
 */

void generate_random_key(uint8_t * key)
{
	int fd, i;

	if ((fd = open("/dev/urandom", O_RDONLY)) < 0) {
    		perror("open /dev/urandom");
        	exit(-1);
    	}

    	if (read(fd, key, MAX_KEY_LEN) != MAX_KEY_LEN) {
        	perror("read() from /dev/urandom");
        	exit(-1);
    	}

    	close(fd);

    	printf("[+] Generated layer 2 key (256BIT) for host executable: ");
    	for (i = 0; i < MAX_KEY_LEN; i++)
        	printf("%02x", key[i]);
    	printf("\n");
}

int encrypt_stream(crypto_t * crypto, uint8_t * plaintext, size_t len,
                   crypto_type_t type)
{
    	size_t i;
    	uint8_t *ciphertext = malloc(len);
	struct timeval tv;

    	generate_random_key(crypto->key);

    	crypto->type = type;
    	crypto->len = len;
    	crypto->keylen = MAX_KEY_LEN;

    	switch (type) {
    	case SALSA:
		gettimeofday(&tv, NULL);
		srand(tv.tv_usec);
		crypto->iv[0] = rand() & 0xfe;
		
	        gettimeofday(&tv, NULL);
                srand(tv.tv_usec);
		crypto->iv[0] = rand() & 0xfe;
		
		gettimeofday(&tv, NULL);
                srand(tv.tv_usec);
		crypto->iv[1] = rand() & 0xfe;
		
	        gettimeofday(&tv, NULL);
                srand(tv.tv_usec);
		crypto->iv[2] = rand() & 0xfe;
		
	        gettimeofday(&tv, NULL);
                srand(tv.tv_usec);
		crypto->iv[3] = rand() & 0xfe;
		
		gettimeofday(&tv, NULL);
                srand(tv.tv_usec);
		crypto->iv[4] = rand() & 0xfe;
		
	        gettimeofday(&tv, NULL);
                srand(tv.tv_usec);
		crypto->iv[5] = rand() & 0xfe;
		
	        gettimeofday(&tv, NULL);
                srand(tv.tv_usec);
		crypto->iv[6] = rand() & 0xfe;
		
		gettimeofday(&tv, NULL);
		srand(tv.tv_usec);
		crypto->iv[7] = rand() & 0xfe;

        	ECRYPT_keysetup(&crypto->ctx, crypto->key, 256, 64);
        	ECRYPT_ivsetup(&crypto->ctx, crypto->iv);
        	ECRYPT_encrypt_bytes(&crypto->ctx, plaintext, ciphertext,
                             crypto->len);
        	for (i = 0; i < len; i++)
            		plaintext[i] = ciphertext[i];
        break;
    	
	case RABBIT:
        break;
    	
	case HC128:
        break;
    	
	case LEVIATHAN:
        break;
   	
	case RC4:
        	rc4_crypt(crypto->key, plaintext, crypto->len);
        break;
    }

    free(ciphertext);
    return 0;


}

static __inline void swap_bytes(unsigned char *a, unsigned char *b)
{
    unsigned char temp;

    temp = *a;
    *a = *b;
    *b = temp;
}


void rc4_ksa(unsigned char state[], unsigned char key[], int len)
{
    int i, j = 0, t;

    for (i = 0; i < 256; ++i)
        state[i] = i;
    for (i = 0; i < 256; ++i) {
        j = (j + state[i] + key[i % len]) % 256;
        t = state[i];
        state[i] = state[j];
        state[j] = t;
    }
}

void rc4_crypt(unsigned char *key, unsigned char *text,
               unsigned int textlength)
{
    unsigned char S[256];
    unsigned int i, j, keylength;
    for (keylength = 0; *key; keylength++, key++);
    key -= keylength;
    for (i = 0; i < 256; i++)
        S[i] = i;
    rc4_ksa(S, key, keylength);
    for (i = 0, j = 0; textlength > 0; text++, textlength--) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        S[i] ^= S[j];
        S[j] ^= S[i];
        S[i] ^= S[j];
        *text ^= S[(S[i] + S[j]) & 0xFF];
    }
}
