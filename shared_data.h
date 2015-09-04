#include "ecrypt-sync.h"

#define MAX_KEY_LEN (128 >> 2)
#define MAX_SYMNAM_LEN 64
#define MAX_CRYPT_POCKETS 256
#define MAX_NANOMITES 256
#define MAX_CFLOW_ITEMS 256

#define FINGERPRINT_SIZE 512

#define MAX_IV_LEN 8

typedef enum {RC4, SALSA, RABBIT, HC128, LEVIATHAN} crypto_type_t;
typedef enum {NANOMITE_CALL, NANOMITE_JMP, NANOMITE_MOV} nanomite_type_t;

typedef struct {
	Elf64_Addr fnaddr;
	struct {
		uint32_t retOffset;
		uint8_t origByte;
	} retinstr[32];
	int mutation_interval;
} __attribute__((packed)) fn_personality_t;

typedef struct {
        Elf64_Addr startVaddr;
        Elf64_Addr endVaddr;
	int isRet;
        unsigned int size;
        
        char symname[MAX_SYMNAM_LEN];
        
        unsigned char origByte;
        
        int keyLen;
        uint8_t key[MAX_KEY_LEN]; 
	fn_personality_t fn_personality;
	uint32_t retcount;
	int mutation_count;
} __attribute__((packed)) cryptMetaData_t;

typedef struct {
        Elf64_Addr vaddr;
        Elf64_Addr retaddr;
	Elf64_Addr site;
	uint32_t size;
	nanomite_type_t type;
} __attribute__((packed)) nanomite_t;

typedef struct maya_modes {
	unsigned int fnprofile;
	unsigned int speedext;
        unsigned int antiexploit;
        unsigned int antidebug;
	unsigned int fingerprint;
	unsigned int nanomites;
	unsigned int ro_relocs;
        unsigned int layer0;
        unsigned int layer1;
        unsigned int layer2;
        unsigned int layer3;
} __attribute__((packed)) maya_modes_t;

typedef struct maya_cflow {
        unsigned long retLocation;
        unsigned long validRetAddr;
} __attribute__((packed)) maya_cflow_t;

typedef struct ro_relocs {
	uint64_t got_offset;
	uint32_t got_size;
	unsigned long loadbase; // of data segment;
} __attribute__((packed)) ro_relocs_t;

typedef struct cryptInfo {
        unsigned int hostCodeOffset;
        unsigned int hostCodeVaddr;
        unsigned int origDataSize;
        unsigned int origTextSize;
        unsigned char key[MAX_KEY_LEN];
        unsigned int keylen;
	unsigned char iv[MAX_IV_LEN];
	ECRYPT_ctx ctx;
} __attribute__((packed)) cryptInfo_t;


/* We define knowledge_t right in tracer.c since we don't use it in the ./maya code
 */

struct rc4_state {
	unsigned char perm[256];
	unsigned int index1;
	unsigned int index2;
};

typedef struct crypto {
	struct rc4_state rc4_state;
	ECRYPT_ctx ctx;
	crypto_type_t type;
	size_t len;
	unsigned int keylen;
	unsigned int ivlen;
	uint8_t iv [MAX_IV_LEN];
	uint8_t key[MAX_KEY_LEN];
} crypto_t;
