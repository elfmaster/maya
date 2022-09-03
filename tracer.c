/*
 * Copyright (c) 2014, Ryan O'Neill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NOTE: This is the RUNTIME ENGINE.
 * tracer.c is the code for tracer.o which
 * is injected into the protected executable.
 * it must not have any linking to libc and must
 * maintain position independence thus we have
 * hardcoded syscall wrappers.
 */

#include "tracer.h"
#include "shared_data.h"
#include "ecrypt-sync.h"

#include <signal.h>


#define REAL_CPU_DELAY_TIME 0xf000

int global_pid;

#define PAUSE_PARENT _pause() 
#define INIT_MALLOC_SIZE 4096 << 10
#define MAX_HEAP_BINS 8
#define HEAP_BLOCK_SIZE 64 // XXX NOTE: Changed from 512 to 64 (Much more space efficient for hash map)
#define CHUNK_ROUNDUP(x)(x + HEAP_BLOCK_SIZE & ~(HEAP_BLOCK_SIZE - 1))
#define CHUNK_UNUSED_INITIALIZER 0xFFFFFFFF
#define MALLOC_KEY_LEN 0x8 /* Used for encrypted chunks */

/*
 * Simple implementation of Malloc
 **/

/*  
 *  Each bin has a chunk index 'void *indexTable'
 *  which contains an array of 'struct chunkData'.
 *  Chunks are 512 bytes, and no memory request 
 *  ever returns less than a chunk size. This 
 *  works for our purposes, but could obviously
 *  be refined.
 *  
 *  [INDEX 0]___________________________________
           \       \      \              \
 *  [BIN 0][CHUNK][CHUNK][CHUNK][EMPTY][CHUNK]
 *   
 *  [INDEX 1]___________________________________  
 *          \                    \
 *  [BIN 1][CHUNK][EMPTY][EMPTY][CHUNK][EMPTY]
 *
 *  HEAP CHUNK(BLOCK) SIZE: 64B 
 *  MAXIMUM HEAP CAPACITY: 32MB
 *  MAXIMUM ALLOCATION SIZE PER ALLOCATION: 4MB or (4194304 Bytes)
 * 
 */

struct chunkData {
	unsigned long chunkVaddr;
	unsigned int chunkSize;
	unsigned int chunkOffset; 
};

struct mHandle {
	unsigned char *bin;
	unsigned int memOff;
	unsigned int binSize;
	unsigned long baseVaddr;
	void *indexTable;
	struct chunkData *chunkData; // we store these in indexTable mapping
	int chunkCount;
	int initialized;
}; // mHandle[MAX_HEAP_BINS] = {[0 ... MAX_HEAP_BINS - 1] = 0};

struct mHandle mHandle[MAX_HEAP_BINS] __attribute__((section(".data"))) = { [0 ... MAX_HEAP_BINS - 1] = 0};

unsigned int ActiveBin __attribute__((section(".data"))) = 0;
	
/*
 * cryptMetaData_t structs are stored
 * in the data segment of tracer.o and
 * contain encrypted locations, their sizes
 * their keys, etc.
 */

/** Defined in shared_data.h 
typedef struct {
        Elf64_Addr startVaddr;
        Elf64_Addr endVaddr;
        unsigned int size;
        
	char symname[MAX_SYMNAM_LEN];
        
	unsigned char origByte;
	
	int keyLen;
	uint8_t key[MAX_KEY_LEN]; 
} __attribute__((packed)) cryptMetaData_t;
*/
unsigned char decryptRoutine(unsigned long vaddr);

	
int errno;


/*
 * Needed to get eip in a PIC way
 */
extern unsigned long get_ip;
unsigned long get_rip(void);

/*
 * syscall wrapper function prototypes
 */
int _modify_ldt(long, void *, unsigned long);
int _fstat(long, void *);
long _lseek(long, long, unsigned int);
void Exit(long);
void *_mmap(unsigned long, unsigned long, unsigned long, unsigned long,  long, unsigned long);
long _open(char *, unsigned long);
long _write(long, char *, unsigned long);
int _read(long, char *, unsigned long);
long maya_ptrace(long, long, void *, void *);
int _wait4(long, long *, long, long *);
void _pause(void);
int _clone(unsigned long, unsigned long, unsigned int, long);
int _getpid(void);
int _getppid(void);
long _kill(unsigned int, unsigned int);
int maya_sigaction(unsigned int, struct sigaction *, struct sigaction *);
int maya_gettimeofday(void *, void *);

/*
 * libc functions we re-implement
 */
void * paranoid_memdup(void *, unsigned int);
void paranoid_move(void *, void *, unsigned int);
int Memcmp(const void *, const void *, size_t);
void _strcpy(char *, char *);
int _strcmp(const char *, const char *);
int _strncmp(const char *s1, const char *s2, size_t n);
int _memcmp(const void *s1, const void *s2, unsigned int n);
char * _strrchr(const char *cp, int ch);
char *_strchr(const char *s, int c);
void _memcpy(void *, void *, unsigned int);
void Memset(void *, unsigned char, unsigned int);

void FreeMem(void *);
void initMalloc(void);
void * Malloc(unsigned int);
int malloc_crypto_load(unsigned char *, const void *, unsigned int, void *);
void * malloc_crypto_store(unsigned char *, const void *, unsigned int);


int _printf(char *fmt, ...);
int _sprintf(char *, char *, ...);
char * itoa(long x, char *t);
char * itox(long x, char *t);
int _puts(char *str);
size_t _strlen(char *s);
char * _fgets(char *, size_t, int, long *);


/* salsa funcs */
static void salsa20_wordtobyte(u8 output[64],const u32 input[16]);
void ECRYPT_init(void);
void ECRYPT_keysetup(ECRYPT_ctx *x,const u8 *k,u32 kbits,u32 ivbits);
void ECRYPT_ivsetup(ECRYPT_ctx *x,const u8 *iv);
void ECRYPT_encrypt_bytes(ECRYPT_ctx *x,const u8 *m,u8 *c,u32 bytes);
void ECRYPT_decrypt_bytes(ECRYPT_ctx *x,const u8 *c,u8 *m,u32 bytes);
void ECRYPT_keystream_bytes(ECRYPT_ctx *x,u8 *stream,u32 bytes);


/*
 * custom functions for tracer
 */
int create_thread(void (*fn)(void *), void *data); // similar to pthread_create()
static inline int pid_read(int, void *, const void *, size_t); // reads in data using ptrace(PEEK_TEXT, ...
void exit_thread(void);	// threads must exit with exit_thread()
void maya_timeskew(void);

/*
 * Obfuscation functions: Opaque branches (Can get alot more complex than this)
 */
static inline void opaque_jmp_1() __attribute__((always_inline));
static inline void opaque_jmp_2() __attribute__((always_inline));
static inline void opaque_jmp_3() __attribute__((always_inline));

/*
 * Termination code
 */
typedef enum {DEADCODE, DEADBEEF, ACID, LSD25, LEETCODE} crash_type_t;

static inline void terminate(crash_type_t) __attribute__((always_inline));

/*
 * Global initialized data section structures
 * knowledge being the primary database of intelligence.
 */
typedef struct knowledge {
	Elf64_Addr hostEntry; // original entry point 
	cryptInfo_t cryptinfo_text;  // crypt info for .text section
	cryptInfo_t cryptinfo_data;  // crypt info for .data section
	cryptInfo_t cryptinfo_rodata; // crypt info for .rodata section
	cryptInfo_t cryptinfo_plt;   // crypt info for .plt section
	unsigned char fingerprint[FINGERPRINT_SIZE]; //fingerprint for host
	unsigned int crypt_item_count; // number of encrypted functions
	unsigned int cflow_item_count; // number of cflow entries for anti-ROP
	ro_relocs_t ro_relocs;     // info for applying read-only relocations
        cryptMetaData_t encryptedLocations[MAX_CRYPT_POCKETS];  //array of structs for each encrypted function
        nanomite_t nanomite[MAX_NANOMITES];  // array of emulated branch instruction info
} __attribute__((packed)) knowledge_t;

/*
 * The sizes of Maya internal functions that are encrypted
 */
typedef struct fsizes {
	unsigned int trace_thread;
	unsigned int fingerprint;
	unsigned int verify_fingerprint;
} __attribute__((packed)) fsizes_t;

fsizes_t __attribute__((section(".data"))) functionSizes = {0x00};

/*
 * Simple hash table info
 */
#define HASHLEN 1783

typedef enum {BEGIN_ROUTINE,END_ROUTINE,INACTIVE,WAITING,UNKNOWN} funcState_enum_t;
struct routineState {
	funcState_enum_t funcState;
	void * (*cb)(void *);
};

typedef enum {CFLOW_HASH,FSTATE_HASH,MISC_HASH} hash_act_t;
typedef enum {VALID_RETURN,INVALID_RETURN,MARKED_CONSTRAINT,UNKNOWN_LOC,UNDEFINED_ENTRY} cfi_verdict_t;

typedef struct hashLink
{
	/*
	 * data is currently an unused
	 * element.
	 */
	void *data;

	/*
	 ** Used only for maya_cflow_t 
	 ** hash instances.
	 */
	unsigned long retLocation; 
	unsigned long validRetAddr;

		
	/*
	 * Key will be either pid, or retLocation
	 */
	unsigned int key;
	
	
	/*
	 ** Used for context function state
	 */
	struct routineState state;
        struct hashLink *next;
} hashlink_t;

typedef struct hash_type
{
        unsigned int elements;
	unsigned int hval; 
	unsigned long key;
        hashlink_t *head;
}       HASH;


typedef struct dummy_struct {
	unsigned long d1[4096];
} dummy_struct_t;
	

/*
 * These are dummy structs that serve no purpose
 * but we run a cipher on them to decoy hackers
 * from the real material.
 */
dummy_struct_t dummy1 __attribute__((section(".data"))) = { 0x00 };
dummy_struct_t dummy2 __attribute__((section(".data"))) = { 0x00 };

/*
 * The data that goes into the tls_data_t is injected 
 * into the .tdata section in the necessary spots during
 * the protection phase. The tracing thread utilizes this.
 */
knowledge_t knowledge __attribute__((section(".data"))) = { 0x00 };

struct safe_access {
	knowledge_t *knowledge;
	void *knowledge_saveptr;

	maya_cflow_t *cflow;
	void *cflow_saveptr;
} safe __attribute__((section(".data"))) = { 0x00 };

maya_modes_t maya_modes __attribute__((section(".data"))) = { 0x00 };

maya_cflow_t maya_cflow[MAX_CFLOW_ITEMS] __attribute__((section(".data"))) = { 0x00 };


typedef unsigned long long _ull;

struct bootstrap_data {
	unsigned char *stack;
	_ull rsp;
	_ull rax;
	_ull rcx;
	_ull rdx;
	_ull rbx;
	_ull rdi;
	_ull rsi;
	_ull r8;
	_ull r9;
	_ull r10;
	_ull r11;
	_ull r12;
	_ull r13;
	_ull r14;
	_ull r15;
} __attribute__ ((packed));

struct bootstrap_data bootstrap __attribute__((section(".data"))) = { 0x00 };
extern unsigned long real_start;

void maya_main(void);

static inline char **getenvp(void) __attribute__((always_inline));
static inline char **getenvp(void)
{
	long *args;
	long *envs;
	long *rbp;
	int argc;
	char **envp;

        /* Extract argc from stack */
        asm __volatile__("mov 8(%%rbp), %%rcx " : "=c" (argc));
     
        /* Extract argv from stack */
        asm __volatile__("lea 16(%%rbp), %%rcx " : "=c" (args));
        
 	/* Extract envp from stack */       
        asm __volatile__("lea 40(%%rbp), %%rcx " : "=c" (rbp));
        
        rbp += ((argc * sizeof(void *)) >> 3);
        envs = (long *)rbp;
	envp = (char **)envs;
	
	return envp;
}

/*
 * ***** ENTRY POINT *****
 * This is where the host executable transfers control to...
 * where our tracing engine must carefully preserve the register
 * state before spawning a thread, and beginning a trace on the
 * original entry point.
 */
int _start(void)
{

	/*
	 * This is likely the ugliest code found in mayas mind.
	 * The preserving of registers, we must restore them before
	 * the tracing thread sets rip to the entry point.
	 */
	
	__asm__ __volatile__("push %%rax	\t\n"
			     "mov 8(%%rsp), %0\t\n"
			     "add $0x8, %%rsp	" : "=r"(bootstrap.rax));
	
	__asm__ __volatile__("push %%rsp	\n"
		"pop %0		  " : "=r"(bootstrap.rsp));
	
	__asm__ __volatile__("push %%rcx	\n"
		"pop %0		  " : "=r"(bootstrap.rcx));
	
	__asm__ __volatile__("push %%rdx	\n"
		"pop %0		  " : "=r"(bootstrap.rdx));
	
	__asm__ __volatile__("push %%rbx	\n"
		"pop %0		  " : "=r"(bootstrap.rbx));
	
	__asm__ __volatile__("push %%rdi	\n"
		"pop %0		  " : "=r"(bootstrap.rdi));
	
	__asm__ __volatile__("push %%rsi	\n"
		"pop %0		  " : "=r"(bootstrap.rsi));
	
	__asm__ __volatile__("push %%r8	\n"
		"pop %0		  " : "=r"(bootstrap.r8));
	
	__asm__ __volatile__("push %%r9	\n"
		"pop %0		  " : "=r"(bootstrap.r9));
	
	__asm__ __volatile__("push %%r10	\n" 
		"pop %0		  " : "=r"(bootstrap.r10));
	
	__asm__ __volatile__("push %%r11	\n"
		"pop %0		  " : "=r"(bootstrap.r11));
	
	__asm__ __volatile__("push %%r12	\n"
		"pop %0		  " : "=r"(bootstrap.r12));
 
        __asm__ __volatile__("push %%r13     \n"
                "pop %0           " : "=r"(bootstrap.r13));

        __asm__ __volatile__("push %%r14     \n"     
                "pop %0           " : "=r"(bootstrap.r14));
	
	__asm__ __volatile__("push %%r15	\n"
		"pop %0		  " : "=r"(bootstrap.r15));

	

	__asm__(".globl real_start\n"
        	"real_start:\n"
        	"call maya_main\n");

}

	
static inline void delay(int v)
{
        int i, j;
        for (i = 0; i < v * 5000; i++)
                for (j = 0; j < 50000; j++)
                        ;
}

void maya_timeskew(void)
{
	int i, j;
	for (i = 0; i < 1000; i++)
		for (j = 0; j < 2000; j++)
			;
}


static inline int pid_read(int pid, void *dst, const void *src, size_t len)
{

        int sz = len / sizeof(void *);
        int rem = len % sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
	unsigned long word;

	while (sz-- != 0) {
                word = maya_ptrace(PTRACE_PEEKTEXT, pid, (long *)s, NULL);
		if (word == -1) 
                        return -1;
               *(long *)d = word;
                s += sizeof(long);
                d += sizeof(long);
        }
        
        return 0;
}

int pid_write(int pid, void *dest, const void *src, size_t len)
{
        size_t rem = len % sizeof(void *);
        size_t quot = len / sizeof(void *);
        unsigned char *s = (unsigned char *) src;
        unsigned char *d = (unsigned char *) dest;
        
        while (quot-- != 0) {
                if ( maya_ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1 )
                        goto out_error;
                s += sizeof(void *);
                d += sizeof(void *);
        }

        if (rem != 0) {
                long w;
                unsigned char *wp = (unsigned char *)&w;

                w = maya_ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                if (w == -1 && errno != 0) {
                        d -= sizeof(void *) - rem;

                        w = maya_ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                        if (w == -1 && errno != 0)
                                goto out_error;

                        wp += sizeof(void *) - rem;
                }

                while (rem-- != 0)
                        wp[rem] = s[rem];

                if (maya_ptrace(PTRACE_POKEDATA, pid, (void *)d, (void *)w) == -1)
                        goto out_error;
        }

        return 0;

out_error:
#if DEBUG
	_printf("[MAYA]: pid_write() failed\n");
#endif
        return -1;
}

/*
 * Code to get system fingerprint and check it
 */
int verify_fingerprint(void)
{
	int fd, i;
	unsigned char mem[FINGERPRINT_SIZE];
	unsigned char fingerprint[FINGERPRINT_SIZE];
	unsigned char *fp = fingerprint;

	if ((fd = _open("/proc/iomem", O_RDONLY)) < 0) {
#if DEBUG
		_printf("[MAYA] Unable to open /proc/iomem for reading\n");
#endif
		return -1;
	}

	_read(fd, mem, FINGERPRINT_SIZE);
	
	for (i = 0; i < FINGERPRINT_SIZE; i++) 
		fp[i] = mem[i];
	
#if HEAP_CRYPTO
	if (Memcmp(fingerprint, safe.knowledge->fingerprint, FINGERPRINT_SIZE) == 0) {
		return 1;
	}
#else
	if (Memcmp(fingerprint, knowledge.fingerprint, FINGERPRINT_SIZE) == 0) {
		return 1;
	}
#endif
	return 0;

}

void fingerprint(void)
{
	if (verify_fingerprint() != 1) {
#if DEBUG
        	_printf("[MAYA] Invalid fingerprint, exiting\n");
#endif
                Exit(99);
       } 

}

	
/********* SIMPLE HASH CODE **********/

unsigned int hTrans(unsigned long v)
{
         unsigned int t = (uint32_t)(v *= 1738);
         return t * 33;
}

unsigned int hash(unsigned long v)
{
        return ((hTrans(v) + 31) % HASHLEN);
}


void set_hash_chain_fstate(HASH *h, unsigned long key, funcState_enum_t fstate)
{
	hashlink_t *cur;
	
	for (cur = h[hash(key)].head; cur != NULL; cur = cur->next)
		if (cur->key == key) {
#if VERBOSE_DEBUG
			_printf("[MAYA] set function state: %x\n", fstate);
#endif
			cur->state.funcState = fstate; 

		}

}

cfi_verdict_t get_hash_chain_cfi_retloc(HASH *h, unsigned long key)
{
	hashlink_t *cur;
	
	if (h[hash(key)].elements > 0)
		return MARKED_CONSTRAINT;
	
	return UNKNOWN_LOC;
}
	
cfi_verdict_t get_hash_chain_cfi_retval(HASH *h, unsigned long key, unsigned long retaddr)
{
	hashlink_t *cur;
	
	if (!h[hash(key)].elements)
		return UNDEFINED_ENTRY;

	for (cur = h[hash(key)].head; cur != NULL; cur = cur->next) {
		if (cur->retLocation == key)
			if (cur->validRetAddr == retaddr)
				return VALID_RETURN;
	}
	return INVALID_RETURN;
}

funcState_enum_t get_hash_chain_fstate(HASH *h, unsigned long key /* key is the pid */)
{
	unsigned int i;
	hashlink_t *cur;

	if (!h[hash(key)].elements)
		return -1;

	for (cur = h[hash(key)].head; cur != NULL; cur = cur->next) {
		if (cur->key != key)
			continue;
		return cur->state.funcState;
	}
		
	return (funcState_enum_t)UNKNOWN;
}


int add_hash_item(unsigned long key, HASH *h, unsigned long x, hash_act_t action, void *data)
{
        unsigned int hval = 0;
        hashlink_t *tmp;

        hval = hash(key);
        if ((tmp = (hashlink_t *)Malloc(sizeof(hashlink_t))) == NULL)
                return -1;

        tmp->next = h[hval].head;
        h[hval].head = tmp;
        h[hval].hval = hval;
        h[hval].key = key;

#if DEBUG
	_printf("Added item to hash: hval(%u) key(%d <-> 0x%x) HTYPE: %s\n",  hval, h[hval].key, h[hval].key, action == FSTATE_HASH ? "FSTATE" : "CFLOW");
        
#endif
	
	switch(action) {
		case FSTATE_HASH:
			tmp->state.funcState = INACTIVE;
        		tmp->data = data;
  			tmp->key = key;
			break;
		
		case CFLOW_HASH:
			tmp->retLocation = key;
			tmp->validRetAddr = x;
			tmp->key = key;
			break;
		
		case MISC_HASH:
			tmp->data = data;
			tmp->key = key;
			break;
		
		default:
			return -1;
	}
	
        h[hval].elements++;
   
        return 0;

}

HASH * init_hash_table(void)
{
        HASH *link;
        int i;

        if ((link = (HASH *)Malloc(HASHLEN * sizeof(HASH))) == NULL)
                return NULL;

        for (i = 0; i < HASHLEN; i++) {
                link[i].elements = 0;
                link[i].head = NULL;
        }

        return link;
}

static inline int quick_branch(unsigned int x, unsigned int y, unsigned int z)
{
	unsigned int branch[2];
	
	branch[0] = z;
	branch[1] = y;
	
	return branch[!((!x))];
}

/*
 * pt_emulate_call() emulates a call instruction using
 * ptrace.
 */
void pt_emulate_call(int pid, unsigned long vaddr, unsigned long retaddr)
{
        struct user_regs_struct pt_reg;

#if DEBUG
	_printf("[MAYA] Emulating 'call %x'\n", vaddr);
#endif

	maya_ptrace(PTRACE_GETREGS, pid, NULL, &pt_reg);
	
	/* 
	 * push return address onto stack
	 */
	_memcpy((void *)pt_reg.rsp, (void *)&retaddr, sizeof(void *));
	pt_reg.rsp -= sizeof(void *);
	
	/*
	 * Set instruction pointer to target
	 */
	pt_reg.rip = vaddr;
	
	maya_ptrace(PTRACE_SETREGS, pid, NULL, &pt_reg);
	maya_ptrace(PTRACE_CONT, pid, NULL, NULL);
}

void pt_emulate_jmp(int pid, unsigned long vaddr)
{ 
	struct user_regs_struct pt_reg;
#if DEBUG
	_printf("[MAYA] Emulating 'jmp %x'\n", vaddr);
#endif

	maya_ptrace(PTRACE_GETREGS, pid, NULL, &pt_reg);
	
	pt_reg.rip = vaddr;
	
	maya_ptrace(PTRACE_SETREGS, pid, NULL, &pt_reg);
	maya_ptrace(PTRACE_CONT, pid, NULL, NULL);
}
	

int trap_count __attribute__ ((section(".data"))) = {0x00};
	
static void sigcatch(int sig, siginfo_t *siginfo, void *ctx)
{
#if DEBUG
	_printf("Caught trap!\n");
#endif
	trap_count++;

}

/*
 * Unfinished
 */
int detect_pin(unsigned int pid)
{
	char path[256], buf[512], *p;
        int fd, i;
        long offset = 0;
	int vsyscall = 0;
	
	_sprintf(path, "/proc/%d/maps", pid);
        fd = _open(path, O_RDONLY); // we add this as a workaround to weird fd bug
        if (fd < 0)
                return -1;
	
	while (_fgets(buf, sizeof(buf), fd, &offset)) {
		if ((p = _strchr(buf, '[')) != NULL) {
			if (!_strncmp(p, "[vdso]", 6)) {
				_fgets(buf, sizeof(buf), fd, &offset);
				if ((p = _strchr(buf, '[')) != NULL) {
					if (!_strncmp(p, "[vvar]", 6)) {
						terminate(LSD25);
						return 1;
					}
					else
						return 0;
				} else
					return 0;
			}
		}
					
	}
	return 0;
}

int detect_thread_debuggers(unsigned int pid)
{
	char buf[512], *p;
	int fd, i;
	long offset = 0;

 	fd = _open("/proc/self/status", O_RDONLY); // we add this as a workaround to weird fd bug
	if (fd < 0) 
		return -1;
	for (i = 0; i < 7; i++)
		_fgets(buf, sizeof(buf), fd, &offset);
	_close(fd);
	
	/*
	 * If the string looks like "TracerPid: 0\n" then we aren't being
	 * traced by a debugger on the cloned thread 
	 */
	p = &buf[11];
	if (*p == '0') {
		p++;
		if (*p == 0xA) 
			return 0;
	}
	
	/*
	 * If we made it here, then we are being traced
	 */
#if DISPLAY_MSG
	_printf("[MAYA] I shall smite thee debugger into oblivion\n");
#endif
	asm volatile("movq $0x1337C0DE, %rcx\n"
		     "movq %rcx, (%rsp)\n"
		     "ret");
	return 1;
}

static inline void terminate(crash_type_t crash_type)
{
	switch(crash_type) {
		case DEADCODE:
			__asm__ volatile("mov $0xDEADC0DE, %rcx\n"
					 "mov %rcx, (%rsp)\n"
					 "ret");
			break;
		case ACID:
			__asm__ volatile("mov $0x4C1DC0DE, %rcx\n"
					 "mov %rcx, (%rsp)\n"
					 "ret");
			break;
		case LSD25:
			__asm__ volatile("mov $0x15D25, %rcx\n"
					 "mov %rcx, (%rsp)\n"
					 "ret");
			break;
		case DEADBEEF:
			__asm__ volatile("mov $0xDEADBEEF, %rcx\n"
					 "mov %rcx, (%rsp)\n"
					 "ret");
			break;
		case LEETCODE:
			__asm__ volatile("mov $0x1337C0DE, %rcx\n"
					 "mov %rcx, (%rsp)\n"
					 "ret");
			break;
	}
	_kill(_getppid(), -1);

}
void set_prctl_protections(void)
{
	/*
	 * We set the thread name to something other than
	 * the pids original program name. This is just
	 * a form of obscurity to possibly prevent someone
	 * from seeing a thread is created and related
	 * to Maya. XXX should use CLONE_NEWPID as well
	 * to disjoint its tid from the process thread group.
	 */
	char tidName[] = {'l', 's', 'd', '\0'};
	
	_prctl(PR_SET_NAME, (char *)tidName, 0, 0, 0);
	
	if (_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) {
#if DEBUG
		_printf("_prctl failed\n");
#endif
	}

}

#define MAX_PIDS 12

void trace_thread(void *arg)
{
	char *dptr;
	struct user_regs_struct pt_reg;
	long status, ptraceOpts;
	int i, j, k, b;
	unsigned char *decryptBuffer;
	unsigned long stackAddr;
	int functionBegin = 0, maya_bp = 0, iter = 0;

	siginfo_t siginfo;

#if DETECT_EMU
	unsigned int elapsed, t1;
	struct {
		long sec;
		long usec;
	} tv;
#endif


	int p_index = 1; // pid index
	int currpid, newpid, parent;
	HASH *cfi;
	HASH *ctx = init_hash_table();
	if (ctx == NULL) {
#if DEBUG
		_printf("[MAYA] Internal (ctx)hash table allocation failure\n");
#endif
		exit_thread();
	}
	
	if (maya_modes.antiexploit) {
		cfi = init_hash_table();
		if (cfi == NULL) {
#if DEBUG
			_printf("[MAYA] Internal (cfi)hash table allocation failure\n");
#endif
			exit_thread();
		}
		//for (i = 0; i < MAX_CFLOW_ITEMS; i++) 
#if HEAP_CRYPTO
		for (i = 0; i < safe.knowledge->cflow_item_count; i++)
#else
	 	for (i = 0; i < knowledge.cflow_item_count; i++)
#endif
			if (maya_cflow[i].retLocation && maya_cflow[i].retLocation != 0xDEADC0DE)
				add_hash_item(
				maya_cflow[i].retLocation,  /* Address of 'ret' instruction */
				(HASH *)cfi, 		    /* hash pointer */
				maya_cflow[i].validRetAddr, /* valid return address */
				CFLOW_HASH,		    /* hash action */
				 NULL); 
	}
	
	/*
	 * Setup simple SIGTRAP detection
	 */
	
#if THREAD_SIGTRAP_TEST
	struct sigaction act, oldact;
	act.sa_flags = SA_SIGINFO;
 	Memset((sigset_t *)&act.sa_mask, 0, sizeof(sigset_t));
	act.sa_sigaction = (void (*)(int, siginfo_t *, void *))sigcatch;
#if DEBUG
	_printf("[MAYA] act.sa_sigaction: %x\n", act.sa_sigaction);
#endif
	if (maya_sigaction(SIGTRAP, (struct sigaction *)&act, (struct sigaction *)NULL) == -1) {
#if DEBUG
		_printf("[MAYA] sigaction failure\n");
#endif
		exit_thread();
	}
#endif
 	
	/*
	 * Get the parent PID
	 */
	int pid = _getppid();

#if DEBUG
	_printf("[MAYA] Parent pid: %d\n", pid);
#endif
	if (!maya_modes.layer0)
		add_hash_item(pid, ctx, 0, FSTATE_HASH, NULL);
	
	if (maya_ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
#if DISPLAY_MSG
		_printf("[MAYA] The Veil of Maya shall veil still; To conceil what the debugger might reveal\n");
#endif
		terminate(LEETCODE);
	}
	
	/*
	 * NOTE: PTRACE_O_EXITKILL is so that if the tracer exits (For whatever reason) a sigkill is sent
	 * to the tracee. 
	 */

	ptraceOpts = PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT|PTRACE_O_EXITKILL;
	maya_ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)ptraceOpts);
	
	maya_ptrace(PTRACE_GETREGS, pid, 0, &pt_reg);
	
	/*
  	 * We set the prctl() protections after we have attached with ptrace
	 * to the parent process. If we did prctl() before hand, the ptrace
	 * attach wouldn't have worked.
	 */
	set_prctl_protections();
	
	/* Restore 64bit general regs */
	pt_reg.rax = bootstrap.rax;
	pt_reg.rbx = bootstrap.rbx;
	pt_reg.rcx = bootstrap.rcx;
	pt_reg.rdx = bootstrap.rdx;
	pt_reg.rsi = bootstrap.rsi;
	pt_reg.rdi = bootstrap.rdi;
	pt_reg.r8  = bootstrap.r8;
	pt_reg.r9  = bootstrap.r9;
	pt_reg.r10 = bootstrap.r10;
	pt_reg.r11 = bootstrap.r11;
	pt_reg.r12 = bootstrap.r12;
	pt_reg.r13 = bootstrap.r13;
	pt_reg.r14 = bootstrap.r14;
	pt_reg.r15 = bootstrap.r15;
	
	/* Restore stack ptr and rip */
	pt_reg.rsp = bootstrap.rsp + sizeof(void *);
	
	/*
	 * layer0 doesn't do any encryption so we can't use
	 * the encrypted heap in that case.
	 */
	if (maya_modes.layer0)
		pt_reg.rip = knowledge.hostEntry;
	else {
#if HEAP_CRYPTO
		pt_reg.rip = safe.knowledge->hostEntry;
#else
		pt_reg.rip = knowledge.hostEntry;
#endif
	}


	/* Load our saved register state and begin tracing  
	 * process control flow! */
	parent = currpid = pid;
	maya_ptrace(PTRACE_SETREGS, pid, 0, (void *)&pt_reg);
cont:
	//if (currpid != parent)
	//	maya_ptrace(PTRACE_SYSCALL, currpid, 0, 0);
	//else
	maya_ptrace(PTRACE_CONT, currpid, 0, 0);
waiting:
	currpid = _wait4(-1, (long *)&status, __WALL, 0);
	
#if DETECT_PIN
	detect_pin(_getppid());
#endif

#if THREAD_ANTIDEBUG
	detect_thread_debuggers(_getppid());
#endif
	maya_ptrace(PTRACE_GETSIGINFO, currpid, 0, &siginfo);
#if DEBUG
	_printf("[MAYA] ptrace signal %x\n", siginfo.si_signo);
#endif
	switch(siginfo.si_signo) {
		case 0x1:
		case 0x2:
		case 0x3:
		case 0x4:
		case 0x5:
		case 0x6:
			break;
	}
			
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { 
			
		if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_FORK << 8)) {
			maya_ptrace(PTRACE_GETEVENTMSG, currpid, NULL, (void *)&newpid);
#if DEBUG
			_printf("newpid: %d currpid: %d\n", newpid, currpid);
#endif
			add_hash_item(newpid, ctx, 0, FSTATE_HASH, NULL);
			maya_ptrace(PTRACE_SETOPTIONS, newpid, NULL, (void *)ptraceOpts);
			maya_ptrace(PTRACE_CONT, newpid, NULL, NULL);
			goto cont;
		} else 
		if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
			maya_ptrace(PTRACE_GETEVENTMSG, currpid, NULL, (void *)&newpid);
			
#if DEBUG
			_printf("newtid: %d currpid: %d\n", newpid, currpid);
		
#endif	
			if (add_hash_item(newpid, ctx, 0, FSTATE_HASH, NULL) < 0) {
#if DEBUG
				_printf("[MAYA] Internal hash table failure\n");
#endif
				exit_thread();
			}
			maya_ptrace(PTRACE_SETOPTIONS, newpid, NULL, (void *)ptraceOpts);
			maya_ptrace(PTRACE_CONT, newpid, NULL, NULL);
			goto cont;
		} else
		if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
			maya_ptrace(PTRACE_GETEVENTMSG, currpid, NULL, (void *)&newpid);
				/* We don't want the parent to exit
				 * until the children are done.
				 */
			//	maya_ptrace(PTRACE_SETOPTIONS, newpid, NULL, (void *)ptraceOpts);
			//	maya_ptrace(PTRACE_CONT, newpid, NULL, NULL);
				goto cont;
				
		} else
		if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			maya_ptrace(PTRACE_GETEVENTMSG, currpid, NULL, (void *)&newpid);
			
#if DEBUG
			_printf("[MAYA] execve() pid: %d\n", newpid);
#endif
			maya_ptrace(PTRACE_SETOPTIONS, newpid, NULL, (void *)ptraceOpts);
			maya_ptrace(PTRACE_CONT, newpid, NULL, NULL);
			goto cont;
		} else
		if (WIFEXITED(status)) {
#if DEBUG
			_printf("Child: %d exited\n", currpid);
#endif
		}
		
		
		/*
		 * Simple emulation detection 
		 * This emulation detection is perhaps unwarranted
		 * since there are other inherent problematic parts
		 * of Maya that naturally cause hiccups with emulators.
		 */
	
#ifdef DETECT_EMU
		/*
		 * XXX Incredible performance hit
		 */
		if ((iter++ & 31) == 0) {
                	maya_gettimeofday(&tv, NULL);
                	t1 = tv.usec;
			maya_timeskew();
                	maya_gettimeofday(&tv, NULL);
			elapsed = tv.usec - t1;
			if ((elapsed & 0xFFFF) > REAL_CPU_DELAY_TIME) {
				terminate(LSD25);

			}
		}
#endif

#ifdef THREAD_SIGTRAP_TEST
			/*
		 	 * int3 debugger detection
		    	 */
#if DEBUG
			_printf("[MAYA] sigaction() newact: %x oldact: %x\n", act.sa_sigaction, oldact.sa_sigaction);		
		
#endif	
			maya_sigaction(SIGTRAP, (struct sigaction *)&act, (struct sigaction *)NULL);

			__asm__ volatile("int3");
			if (!trap_count) {
				terminate(ACID);
			}
			
#endif
		
		maya_bp = 0;
		maya_ptrace(PTRACE_GETREGS, currpid, 0, (void *)&pt_reg);
		
#if THREAD_ANTIDEBUG
		detect_thread_debuggers(_getpid());
#endif

		if (maya_modes.layer0)
			goto transfer;

		set_hash_chain_fstate(ctx, currpid, END_ROUTINE);
#if HEAP_CRYPTO
		for (i = 0; i < safe.knowledge->crypt_item_count; i++) {
#else
		for (i = 0; i < knowledge.crypt_item_count; i++) {
#endif
			/*
			 * Is the instruction pointer at either the first or last instruction? If so then 
			 * a crypto transform needs to happen: DECRYPT OR ENCRYPT
			 */
#if HEAP_CRYPTO
			if (safe.knowledge->encryptedLocations[i].startVaddr == pt_reg.rip - 1 ||
				safe.knowledge->encryptedLocations[i].endVaddr == pt_reg.rip - 1) {
#else
			if (knowledge.encryptedLocations[i].startVaddr == pt_reg.rip - 1 || knowledge.encryptedLocations[i].endVaddr == pt_reg.rip - 1) {
	
#endif

#if HEAP_CRYPTO			
				if (safe.knowledge->encryptedLocations[i].startVaddr == pt_reg.rip - 1)
#else
				if (knowledge.encryptedLocations[i].startVaddr == pt_reg.rip - 1)
#endif
					set_hash_chain_fstate(ctx, currpid, BEGIN_ROUTINE);
#if DEBUG	
				maya_bp++;
				if (!maya_modes.layer0) {
					if (get_hash_chain_fstate(ctx, currpid) == BEGIN_ROUTINE)
#if HEAP_CRYPTO
						_printf("[MAYA] Decrypting function call %s [%x] with key: ",
						safe.knowledge->encryptedLocations[i].symname, safe.knowledge->encryptedLocations[i].startVaddr);
#else
						_printf("[MAYA] Decrypting function call %s [%x] with key: ", 
						knowledge.encryptedLocations[i].symname, knowledge.encryptedLocations[i].startVaddr);
#endif
					else
#if HEAP_CRYPTO
						_printf("[MAYA] Encrypting function call %s [%x] with key: ",
						safe.knowledge->encryptedLocations[i].symname, safe.knowledge->encryptedLocations[i].startVaddr);
#else
						_printf("[MAYA] Encrypting function call %s [%x] with key: ",
						knowledge.encryptedLocations[i].symname, knowledge.encryptedLocations[i].startVaddr);
#endif
					for (j = 0; j < 16; j++)
						_printf("%x", knowledge.encryptedLocations[i].key[j]);
					_printf("\n");
				} 
		
#endif
#if AGRESSIVE_ANTIDEBUG
		               detect_thread_debuggers(_getpid());
#endif

				/*
				 * Copy encrypted/decrypted function into buffer and decrypt/encrypt it
				 */	
#if HEAP_CRYPTO
				dptr = (char *)safe.knowledge->encryptedLocations[i].startVaddr + 0;
				
				if (get_hash_chain_fstate(ctx, currpid) == BEGIN_ROUTINE) {
					dptr[0] = safe.knowledge->encryptedLocations[i].origByte;
					if (safe.knowledge->encryptedLocations[i].isRet)
						dptr[safe.knowledge->encryptedLocations[i].size - 1] = 0xCC; 
				}
#else
		 	        dptr = (char *)knowledge.encryptedLocations[i].startVaddr + 0;

                                if (get_hash_chain_fstate(ctx, currpid) == BEGIN_ROUTINE) {
                                        dptr[0] = knowledge.encryptedLocations[i].origByte;
                                        if (knowledge.encryptedLocations[i].isRet)
                                                dptr[knowledge.encryptedLocations[i].size - 1] = 0xCC;
                                }

#endif

				if (get_hash_chain_fstate(ctx, currpid) == END_ROUTINE) {
				
#if THREAD_ANTIDEBUG
		               detect_thread_debuggers(_getpid());
	
#endif	
					/*
					 * END_ROUTINE signifies we are past the initial int3 breakpoint
					 * and any other breakpoints we hit are signifying either
					 * A. Nanomite
					 * B. Returning to the caller; in which case use CFI to detect exploit attempts
					 */
					if (maya_modes.antiexploit) {
							if (get_hash_chain_cfi_retloc(cfi, pt_reg.rip - 1) == MARKED_CONSTRAINT) {
								_memcpy((unsigned long *)&stackAddr, (unsigned long *)pt_reg.rsp, sizeof(long *));
								
								if (get_hash_chain_cfi_retval(cfi, pt_reg.rip - 1, stackAddr) == INVALID_RETURN) {
#if DISPLAY_CFLOW
									_printf("[MAYA CONTROL FLOW] Detected an illegal return to 0x%x, possible exploitation attempt!\n", stackAddr);
#endif
									
									terminate(DEADCODE);
								
								} 
#if DEBUG
								else
									_printf("[MAYA CONTROL FLOW] Safe ret instruction ocurred to expected target: 0x%x\n", stackAddr); 
								
		
#endif							
							}
					}
#if AGRESSIVE_ANTIDEBUG
			               detect_thread_debuggers(_getpid());
#endif
					/* Set ENCRYPT trap if the function has a return */
#if HEAP_CRYPTO
					if (safe.knowledge->encryptedLocations[i].isRet)
						dptr[safe.knowledge->encryptedLocations[i].size - 1] = 0xC3;
#else
					if (knowledge.encryptedLocations[i].isRet)
						dptr[knowledge.encryptedLocations[i].size - 1] = 0xC3;
#endif
					
					dptr[0] = 0xCC;
				}
				/*
				 * Decrypt/re-encrypt
				 */
				
				if (!maya_modes.layer0) {	
#if HEAP_CRYPTO
				
					if (get_hash_chain_fstate(ctx, currpid) == END_ROUTINE) {
						if (safe.knowledge->encryptedLocations[i].fn_personality.mutation_interval) 
							safe.knowledge->encryptedLocations[i].mutation_count++;
							int mc = safe.knowledge->encryptedLocations[i].mutation_count;
						if (mc == safe.knowledge->encryptedLocations[i].fn_personality.mutation_interval) {
							safe.knowledge->encryptedLocations[i].mutation_count = 0;
							for (b = 0, k = 1; k < safe.knowledge->encryptedLocations[i].size - 1; k++) {
								dptr[k] ^= safe.knowledge->encryptedLocations[i].key[b++];
								if (b > MAX_KEY_LEN - 1)
									b = 0;
							} 
						}
					} else {
						if (safe.knowledge->encryptedLocations[i].mutation_count == 0) {
							for (b = 0, k = 1; k < safe.knowledge->encryptedLocations[i].size - 1; k++) {
								dptr[k] ^= safe.knowledge->encryptedLocations[i].key[b++];
								if (b > MAX_KEY_LEN - 1)
									b = 0;
							}	
						}
					}
					

#else
				
                                        for (b = 0, k = 1; k < knowledge.encryptedLocations[i].size - 1; k++) {
                                                dptr[k] ^= knowledge.encryptedLocations[i].key[b++];
                                                if (b > MAX_KEY_LEN - 1)
                                                        b = 0;
                                	}
#endif

				}
#if AGGRESSIVE_ANTIDEBUG
		               detect_thread_debuggers(_getpid());
#endif
				/*
				 * We must set rip to rip - 1 to step back to execute
				 * the instruction that was covered up with a breakpoint.
				 */
				pt_reg.rip = pt_reg.rip - 1;
				maya_ptrace(PTRACE_SETREGS, currpid, 0, &pt_reg); 
				goto cont;
			}
							
		}
		/*
		 * Detect breakpoints that aren't set by Maya and ignore them :)
		 */
		if (!maya_bp) {
			//_printf("[MAYA] SIGTRAP-> external breakpoint detected\n");
			goto cont;
		}
transfer:
		goto cont;
			
	} 
	if (WIFEXITED(status)) {
		goto out;
	}
out:
	maya_ptrace(PTRACE_DETACH, pid, 0, 0);
	exit_thread();
}

unsigned long createStack(void)
{
	uint8_t *mem;
	mem = _mmap(0, STACK_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS, -1, 0);
	if(mem == MAP_FAILED) {
#if DEBUG
		_printf("[MAYA] Internal stack allocation failed for thread\n");
#endif
		Exit(-1);
	}
	return (unsigned long)(mem + STACK_SIZE);
}



/* *******************************
 * This is where it all starts! **
 *********************************
 */
void maya_main()  
{
	long fd, status;
	unsigned int pid, knowledge_size = sizeof(struct knowledge);
	int i;
	unsigned char *mem, *ciphertext;
	char tidName[256];
	void *tmp;

	ECRYPT_ctx ctx;
	/*
	 * static inline opaque branches
	 * to obfuscate control flow
	 */
	opaque_jmp_1();
	
	_prctl(PR_SET_PTRACER, _getpid());
	/*
	 * Decode knowledge itself within tracer.o, which is itself within the host
	 */
#if HEAP_CRYPTO
	if (maya_modes.layer1) {
		tmp = (void *)(uintptr_t)paranoid_memdup((unsigned char *)&knowledge, knowledge_size);
                mem = (unsigned char *)tmp;

                safe.knowledge = malloc_crypto_store(NULL, tmp, knowledge_size);
                malloc_crypto_load(NULL, (void *)safe.knowledge, knowledge_size, (void *)tmp);
                safe.knowledge_saveptr = safe.knowledge;
                safe.knowledge = tmp;
	}
#endif
	if (maya_modes.layer2) {
		/* PEEL OFF 2nd OUTTER LAYERS
  	 	 */
		
		/*
         	 * Decode knowledge itself within tracer.o, which is itself within the host
         	 */
		
#if HEAP_CRYPTO
		
		/*
		 * We totally destroy any remains of 'knowledge_t' structure from the binary
	 	 * and decode it, then move it into the cryptographic heap segment.
		 */
		tmp = (void *)(uintptr_t)paranoid_memdup((unsigned char *)&knowledge, knowledge_size);
                mem = (unsigned char *)tmp;
                for (i = 0; i < knowledge_size; i++)
                        mem[i] ^= ((0xA * i) & 0xff); 

                safe.knowledge = malloc_crypto_store(NULL, tmp, knowledge_size);
		malloc_crypto_load(NULL, (void *)safe.knowledge, knowledge_size, (void *)tmp);
		safe.knowledge_saveptr = safe.knowledge;
		safe.knowledge = tmp;
		
#else
	

        	mem = (unsigned char *)&knowledge;
       		for (i = 0; i < knowledge_size; i++)
                	mem[i] ^= ((0xA * i) & 0xff);
	
#endif	
		
#if OPAQUE_BRANCHES
		opaque_jmp_2();
#endif
		/*
		 * Decoy 
		 */
		mem = (unsigned char *)&dummy1;
		for (i = 0; i < sizeof(dummy1); i++) 
			mem[i] ^= ((0xB * i) & 0xff);
		
#if HEAP_CRYPTO
		/* RO-RELOCATIONS: mark .jcr, .got, .got.plt, .dynamic, .init, .fini as read-only */
		if (_mprotect((void *)safe.knowledge->ro_relocs.loadbase, 
				    ((safe.knowledge->ro_relocs.got_offset + 
				      knowledge.ro_relocs.got_size + 4095) & ~4095),
				      PROT_EXEC) < 0) {
#if DEBUG
			_printf("[MAYA] _mprotect() failure on read-only relocation areas: Perhaps they are already read-only\n");
#endif
		}
	
#else
		if (_mprotect((void *)knowledge.ro_relocs.loadbase,
				    ((knowledge.ro_relocs.got_offset + 
				      knowledge.ro_relocs.got_size + 4095) & ~4095),
				      PROT_READ) < 0) {
#if DEBUG
			_printf("[MAYA] _mprotect() failure on read-only relocation areas: Perhaps they are already read-only\n");
#endif
		}
#endif

				
		
		
#if OPAQUE_BRANCHES
		opaque_jmp_3();
#endif
		/*
		 * Decode trace_thread()
		 */
        	mem = (unsigned char *)&trace_thread;
        	for (i = 0; i < functionSizes.trace_thread; i++)
                	mem[i] ^= ((0xA * i) & 0xff);
	
#if OPAQUE_BRANCHES	
		opaque_jmp_1();
#endif
		/*
		 * Decoy  
		 */
                mem = (unsigned char *)&dummy2;
                for (i = 0; i < sizeof(dummy2); i++) 
                        mem[i] ^= ((0xB * i) & 0xff);
#if OPAQUE_BRANCHES               
		opaque_jmp_2();
#endif
		/*
		 * Decrypt .text section
		 */
#if HEAP_CRYPTO
		mem = (unsigned char *)(unsigned long)safe.knowledge->cryptinfo_text.hostCodeVaddr;
		safe.knowledge->cryptinfo_text.origDataSize = safe.knowledge->cryptinfo_text.origTextSize;
		_memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&safe.knowledge->cryptinfo_text.ctx, sizeof(ECRYPT_ctx));
		ECRYPT_ivsetup(&ctx, safe.knowledge->cryptinfo_text.iv);
		ECRYPT_decrypt_bytes(&ctx, mem, mem, safe.knowledge->cryptinfo_text.origDataSize);
#else
		mem = (unsigned char *)(unsigned long)knowledge.cryptinfo_text.hostCodeVaddr;
		knowledge.cryptinfo_text.origDataSize = knowledge.cryptinfo_text.origTextSize;
		_memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&knowledge.cryptinfo_text.ctx, sizeof(ECRYPT_ctx));
		ECRYPT_ivsetup(&ctx, knowledge.cryptinfo_text.iv);
		ECRYPT_decrypt_bytes(&ctx, mem, mem, knowledge.cryptinfo_text.origDataSize);
	
#endif

#if OPAQUE_BRANCHES
		opaque_jmp_1();
#endif
		/*
		 * Decoy
	 	 */	
		mem = (unsigned char *)&dummy1;
		for (i = 0; i < sizeof(dummy1); i++) 
			mem[i] ^= ((0xB * i) & 0xff);
#if OPAQUE_BRANCHES
		opaque_jmp_3();
#endif
	       /*
	 	* Decrypt .data section
	 	*/
#if HEAP_CRYPTO
		mem = (unsigned char *)(unsigned long)safe.knowledge->cryptinfo_data.hostCodeVaddr;
		_memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&(safe.knowledge->cryptinfo_data.ctx), sizeof(ECRYPT_ctx));
		ECRYPT_ivsetup(&ctx, safe.knowledge->cryptinfo_data.iv);
		ECRYPT_decrypt_bytes(&ctx, mem, mem, safe.knowledge->cryptinfo_data.origDataSize);

#else
		mem = (unsigned char *)(unsigned long)knowledge.cryptinfo_data.hostCodeVaddr;
                _memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&knowledge.cryptinfo_data.ctx, sizeof(ECRYPT_ctx));
                ECRYPT_ivsetup(&ctx, knowledge.cryptinfo_data.iv);
                ECRYPT_decrypt_bytes(&ctx, mem, mem, knowledge.cryptinfo_data.origDataSize);
	
#endif
#if OPAQUE_BRANCHES
		opaque_jmp_2();
#endif
		/*
		 * Decoy
		 */
		mem = (unsigned char *)&dummy2;
		for (i = 0; i < sizeof(dummy2); i++) 
			mem[i] ^= ((0xB * i) & 0xff);

#if OPAQUE_BRANCHES
		opaque_jmp_1();
#endif
	       /*
	 	* Decrypt .rodata section
 	 	*/
#if HEAP_CRYPTO
		 mem = (unsigned char *)(unsigned long)safe.knowledge->cryptinfo_rodata.hostCodeVaddr;
                _memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&(safe.knowledge->cryptinfo_rodata.ctx), sizeof(ECRYPT_ctx));
                ECRYPT_ivsetup(&ctx, safe.knowledge->cryptinfo_rodata.iv);
                ECRYPT_decrypt_bytes(&ctx, mem, mem, safe.knowledge->cryptinfo_rodata.origDataSize);
#else
		mem = (unsigned char *)(unsigned long)knowledge.cryptinfo_rodata.hostCodeVaddr;
                _memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&knowledge.cryptinfo_rodata.ctx, sizeof(ECRYPT_ctx));
                ECRYPT_ivsetup(&ctx, knowledge.cryptinfo_rodata.iv);
                ECRYPT_decrypt_bytes(&ctx, mem, mem, knowledge.cryptinfo_rodata.origDataSize);
#endif

#if OPAQUE_BRANCHES
		opaque_jmp_2();
#endif
	       /*
	 	* Decrypt .plt section
	 	*/
#if HEAP_CRYPTO
		mem = (unsigned char *)(unsigned long)safe.knowledge->cryptinfo_plt.hostCodeVaddr;
                _memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&(safe.knowledge->cryptinfo_plt.ctx), sizeof(ECRYPT_ctx));
                ECRYPT_ivsetup(&ctx, safe.knowledge->cryptinfo_plt.iv);
                ECRYPT_decrypt_bytes(&ctx, mem, mem, safe.knowledge->cryptinfo_plt.origDataSize);
#else
		mem = (unsigned char *)(unsigned long)knowledge.cryptinfo_plt.hostCodeVaddr;
                _memcpy((ECRYPT_ctx *)&ctx, (ECRYPT_ctx *)&knowledge.cryptinfo_plt.ctx, sizeof(ECRYPT_ctx));
                ECRYPT_ivsetup(&ctx, knowledge.cryptinfo_plt.iv);
                ECRYPT_decrypt_bytes(&ctx, mem, mem, knowledge.cryptinfo_plt.origDataSize);
#endif

#if OPAQUE_BRANCHES	
		opaque_jmp_3();
#endif
		/*
		 * If host fingerprinting is used then decrypt
		 * verify_fingerprint() and fingerprint()
		 */
		if (maya_modes.fingerprint) {
			mem = (unsigned char *)(get_rip() - ((char *)&get_ip - (char *)&fingerprint));
			for (i = 0; i < functionSizes.fingerprint; i++)
				mem[i] ^= ((0xA * i) & 0xff);
	
#if OPAQUE_BRANCHES		
			opaque_jmp_2();
#endif

			mem = (unsigned char *)(get_rip() - ((char *)&get_ip - (char *)&verify_fingerprint));
			for (i = 0; i < functionSizes.verify_fingerprint; i++)
				mem[i] ^= ((0xA * i) & 0xff);
			
#if DEBUG
			_printf("[MAYA] Checking fingerprint\n");
	
#endif
#if OPAQUE_BRANCHES		
			opaque_jmp_3();
#endif
			
			fingerprint();
		}
	}

#if OPAQUE_BRANCHES
	opaque_jmp_1();
#endif

	unsigned long trace_thread_vaddr = get_rip() - ((char *)&get_ip - (char *)&trace_thread);
	
#if OPAQUE_BRANCHES
	opaque_jmp_2();
#endif
	
	fd = _open("/dev/null", O_RDONLY);
	
#if OPAQUE_BRANCHES
	opaque_jmp_3();
#endif

       
#if DEBUG
	_printf("[MAYA] create_thread() -> trace_thread(): %x\n", trace_thread_vaddr);
#endif
	pid = create_thread((void (*)(void *))trace_thread_vaddr, (void *)fd);
	
	
	
	delay(500);
}

void Memset(void *mem, unsigned char byte, unsigned int len)
{
	unsigned char *p = (unsigned char *)mem; 
	int i = len;
	while (i--) {
		*p = byte;
		p++;
	}
}


int Memcmp(const void *s1, const void *s2, size_t n)
{
	unsigned char u1, u2;

    	for ( ; n-- ; s1++, s2++) {
		u1 = * (unsigned char *) s1;
		u2 = * (unsigned char *) s2;
		if ( u1 != u2) {
	    		return (u1 - u2);
		}
    	}
    return 0;
}
void _strcpy(char *dst, char *src)
{
	char *s = src;
	char *d = dst;
	
	while (*s) {
		*d = *s;
		d++, s++;
	}
	*d = '\0';
}
	
void FreeMem(void *mem)
{
	int i, j;
	unsigned long current = (unsigned long)(void *)mem;
	unsigned long vaddr;  
	unsigned int size; 
	unsigned int off; 
		
	for (j = 0; j <= ActiveBin; j++) {
		for (i = 0; i <= mHandle[j].chunkCount; i++) {

			vaddr = mHandle[j].chunkData[i].chunkVaddr;
			size = mHandle[j].chunkData[i].chunkSize;
	
			if (current >= vaddr && current < vaddr + size) {
#ifdef DEBUG	
				_write(1, "free() found chunk, now freeing pointer.\n", 42);
#endif
				/* 
				 * We mark chunkVaddr as CHUNK_UNUSED so that we can use this
				 * chunk again by another allocation request.
				 *
				 */
				mHandle[j].chunkData[i].chunkVaddr = CHUNK_UNUSED_INITIALIZER; 
				
				/* Point it back to the beggining of chunk */
				mem = (void *)vaddr;
				
				/* initialize chunk with 0's as its empty */
				Memset(mem, 0, mHandle[j].chunkData[i].chunkSize);
				
				/* Initialize ptr back to NULL */
				mem = NULL; // initialize pointer to NULL
				goto done;
			}
		}
	}
done:
	return;
			
}

void * malloc_crypto_store(unsigned char *key, const void *data, unsigned int len)
{	
	unsigned int i, k;
	unsigned char *ptr;

	ptr = Malloc(len);
	_memcpy((unsigned char *)ptr, (unsigned char *)data, len);
	/*
	 * In some instances we don't want a key. For instance when
	 * storing the keys that decrypt the keys. Those top level
	 * keys shouldn't be encrypted by yet another set of keys,
	 * as the list would go on of keys to keys.
	 */
	if (key == NULL) {
#ifdef DEBUG
		_printf("[MAYA] malloc_crypto_store. (mode: no key)\n");
#endif
		for (i = 0; i < len; i++) 
			ptr[i] ^= ((0xE * i) & 0xff); 
		return (void *)ptr;
	}
	
#ifdef DEBUG
	_printf("[MAYA] malloc_crypto_store. (mode: 64bit key)\n");
#endif
	for (i = 0, k = 0; i < len; i++) {
		ptr[i] ^= key[k++];
		if (k > MALLOC_KEY_LEN)
			k = 0;
	}
	return (void *)ptr;
	
}

int malloc_crypto_load(unsigned char *key, const void *mem, unsigned int len, void *dst)
{
 	int i, j, k, l, found = 0;
        unsigned long current = (unsigned long)(void *)mem;
        unsigned long vaddr;
        unsigned int size;
	unsigned char *d = (unsigned char *)dst;
	unsigned char *m = (unsigned char *)mem;

        for (j = 0; j <= ActiveBin; j++) {
                for (i = 0; i <= mHandle[j].chunkCount; i++) {

                        vaddr = mHandle[j].chunkData[i].chunkVaddr;
                        size = mHandle[j].chunkData[i].chunkSize;

                        if (current >= vaddr && current < vaddr + size) {
				if (current > vaddr)
					m = (unsigned char *)mem - (current - vaddr);
				if (key == NULL) {
					for (l = 0; l < len; l++)
						d[l] = m[l] ^ ((0xE * l) & 0xff);
					found++;
					break;
				} else {
					for (l = 0, k = 0; l < len; l++) {
						d[l] = m[l] ^ key[k++];
						if (k > MALLOC_KEY_LEN)
							k = 0;
					}
					found++;	
					break;
				}
											
	
			}
		}
	}
#if DEBUG
	if (found)
		_printf("[MAYA] malloc_crypto_load() succeeded\n");
#endif
	return 0;

}			

void * Malloc(unsigned int len)
{
	int i;

	/*
	 * The first call to malloc() will create the first heap bin
	 * with mmap(), and initialize base values.
	 */
	if (mHandle[ActiveBin].initialized == 0) {
		mHandle[ActiveBin].initialized = 1;
		mHandle[ActiveBin].bin = _mmap(0xa000, INIT_MALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);		
		if (mHandle[ActiveBin].bin == MAP_FAILED) {
#if DEBUG
			_write(1, "[!MAYA err] Unable to initialize malloc()\n", 46);
#endif
			Exit(-1);
		}
#if DEBUG
		_printf("[MAYA] internal heap allocation base: 0x%x\n",mHandle[ActiveBin].bin);
#endif
		mHandle[ActiveBin].binSize = INIT_MALLOC_SIZE;
		mHandle[ActiveBin].memOff = 0;
		mHandle[ActiveBin].baseVaddr = (unsigned long)mHandle[ActiveBin].bin;
		mHandle[ActiveBin].indexTable = _mmap(0, INIT_MALLOC_SIZE / (sizeof(long) * 4), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (mHandle[ActiveBin].indexTable == MAP_FAILED) {
#if DEBUG
			_write(1, "[!MAYA err] Unable to initialize malloc() index table\n", 59);
#endif
			Exit(-1);
		}
		mHandle[ActiveBin].chunkData = (struct chunkData *)mHandle[ActiveBin].indexTable;
	}
	
	/*
	 * If we go into this condition it means we have exceeded the current
	 * bin size, and must allocate a new heap bin.
	 */
	if ((mHandle[ActiveBin].memOff + CHUNK_ROUNDUP(len)) >= INIT_MALLOC_SIZE) {
		ActiveBin++;
		if (ActiveBin > MAX_HEAP_BINS - 1) {
#if DEBUG
			_write(1, "[!MAYA err] malloc() has exhausted heap resources\n", 50);
#endif
			Exit(-1);
		}
		mHandle[ActiveBin].bin = _mmap(0, INIT_MALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (mHandle[ActiveBin].bin == MAP_FAILED) {
#if DEBUG
			_write(1, "[!MAYA err] Unable to initialize new malloc() bin mapping\n", 62);
#endif
			Exit(-1);
		} 
		mHandle[ActiveBin].initialized = 1;
		mHandle[ActiveBin].memOff = 0; 
	} 	
	
	/*
	 * First look for a free'd chunk that could be re-used.
	 */
	for (i = 0; i < mHandle[ActiveBin].chunkCount; i++) {
		if (mHandle[ActiveBin].chunkData[i].chunkVaddr == CHUNK_UNUSED_INITIALIZER) {
			if (CHUNK_ROUNDUP(len) <= mHandle[ActiveBin].chunkData[i].chunkSize) {
				mHandle[ActiveBin].chunkData[i].chunkVaddr = (unsigned long)&(mHandle[ActiveBin].bin[mHandle[ActiveBin].chunkData[i].chunkOffset]);
				return &(mHandle[ActiveBin].bin[mHandle[ActiveBin].chunkData[i].chunkOffset]);	
			}
		}
	}

	/*
	 * Do index table entry for malloc request. This helps keep track
	 * of chunks. 
	 */
	mHandle[ActiveBin].chunkData[mHandle[ActiveBin].chunkCount].chunkVaddr = (unsigned long) &(mHandle[ActiveBin].bin[mHandle[ActiveBin].memOff]); 
	mHandle[ActiveBin].chunkData[mHandle[ActiveBin].chunkCount].chunkSize =  CHUNK_ROUNDUP(len);
	mHandle[ActiveBin].chunkData[mHandle[ActiveBin].chunkCount].chunkOffset = mHandle[ActiveBin].memOff + CHUNK_ROUNDUP(len);
	mHandle[ActiveBin].chunkCount++;

	/* Increase offset into heap bin */
	mHandle[ActiveBin].memOff += CHUNK_ROUNDUP(len);

	/* Return pointer to chunk */
	return &(mHandle[ActiveBin].bin[mHandle[ActiveBin].memOff - CHUNK_ROUNDUP(len)]); 		
} 


char * _fgets(char *s, size_t size, int fd, long *offset)
{
        size_t b, i = 0;
        char *p, *buf = s, byte;
        long off = *offset;

        do {
                b = _read(fd, (char *)&byte, 1);
                _lseek(fd, ++off, SEEK_SET);
                if (b < 1)
                        break;
                buf[i++] = byte;
                if (i == size || byte == '\n') {
                        buf[i++] = '\0';
                        break;
                }

        } while(1);

        *offset = off;
        return s;
}

int _sprintf(char *buf, char *fmt, ...)
{
        int in_p, index = 0, len;
        unsigned long dword;
        unsigned int word;
	char *s;
        char numbuf[26] = {0};
        __builtin_va_list alist;

        in_p;

        __builtin_va_start((alist), (fmt));

        in_p = 0;
        while(*fmt) {
                if (*fmt!='%' && !in_p) {
			buf[index++] = *(char *)fmt;
                        in_p = 0;
                }
                else if (*fmt!='%') {
                        switch(*fmt) {
                                case 's':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
					s = itoa(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)itoa(word, numbuf), len);
					index += len;
                                        break;
                                case 'u':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
					s = itoa(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)s, len);
                                        index += len;
                                        break;
                                case 'd':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
					s = itoa(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)s, len);
                                        index += len;
                                        break;
                                case 'x':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
					s = itox(word, numbuf);
					len = _strlen(s);
					_memcpy((char *)&buf[index], (char *)s, len);
                                        index += len;
                                        break;
                                default:	
					buf[index++] = *(char *)fmt;
                                        break;
                        }
                        in_p = 0;
                }
                else {
                        in_p = 1;
                }
                fmt++;
        }
	return 1;

}


int _printf(char *fmt, ...)
{
        int in_p;
        unsigned long dword;
        unsigned int word;
        char numbuf[26] = {0};
        __builtin_va_list alist;

        in_p;

        __builtin_va_start((alist), (fmt));

        in_p = 0;
        while(*fmt) {
                if (*fmt!='%' && !in_p) {
                        _write(1, fmt, 1);
                        in_p = 0;
                }
                else if (*fmt!='%') {
                        switch(*fmt) {
                                case 's':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts((char *)dword);
                                        break;
                                case 'u':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
				case 'd':
					word = (unsigned int) __builtin_va_arg(alist, int);
					_puts(itoa(word, numbuf));
					break;
                                case 'x':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts(itox(dword, numbuf));
                                        break;
                                default:
                                        _write(1, fmt, 1);
                                        break;
                        }
                        in_p = 0;
                }
                else {
                        in_p = 1;
	 	}
                fmt++;
        }
        return 1;
}

char * itoa(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 10) + '0';
                x /= 10;
                i++;
        } while (x!=0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}

char * itox(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 16);

                /* char conversion */
                if (t[i] > 9)
                        t[i] = (t[i] - 10) + 'a';
                else
                        t[i] += '0';

                x /= 16;
                i++;
        } while (x != 0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}

int _puts(char *str)
{
        _write(1, str, _strlen(str));
        _fsync(1);

        return 1;
}

size_t _strlen(char *s)
{
        size_t sz;

        for (sz=0;s[sz];sz++);
        return sz;
}

     
char *_strchr(const char *s, int c)
{
    const char ch = c;

    for ( ; *s != ch; s++)
        if (*s == '\0')
            return 0;
    return (char *)s;
}

char * _strrchr(const char *cp, int ch)
{
    char *save;
    char c;

    for (save = (char *) 0; (c = *cp); cp++) {
	if (c == ch)
	    save = (char *) cp;
    }

    return save;
}
      
int _strncmp(const char *s1, const char *s2, size_t n)
{
    for ( ; n > 0; s1++, s2++, --n)
	if (*s1 != *s2)
	    return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
	else if (*s1 == '\0')
	    return 0;
    return 0;
}
                                               
int _strcmp(const char *s1, const char *s2)
{
        int r = 0;

        while (!(r = (*s1 - *s2) && *s2))
                s1++, s2++;
        if (!r)
                return r;
        return r = (r < 0) ? -1 : 1;
}

int _memcmp(const void *s1, const void *s2, unsigned int n)
{
	unsigned char u1, u2;

	for ( ; n-- ; s1++, s2++) {
		u1 = * (unsigned char *) s1;
		u2 = * (unsigned char *) s2;
	if ( u1 != u2) {
		return (u1-u2);
	}
    }
    return 0;
}

void _memcpy(void *dst, void *src, unsigned int len)
{
        int i;
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;

        for (i = 0; i < len; i++) {
                *d = *s;
                s++, d++;
        }

}

/*
 * paranoid_move() is similar to memcpy() except that it 
 * wipes out the data in the src location, byte by byte
 */
void paranoid_move(void *dst, void *src, unsigned int len)
{
	int i;
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	
	for (i = 0; i < len; i++) { 
		*d = *s;
		*s = '\0';
		s++, d++;
	}

}

void * paranoid_memdup(void *data, unsigned int len)
{
	unsigned char *p = Malloc(len);
	paranoid_move((unsigned char *)p, (unsigned char *)data, len);
	return (void *)p;
}

int _fsync(int fd)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $74, %%rax\n"
                        "syscall" : : "g"(fd));

        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int maya_gettimeofday(void *tv, void *tz)
{
	unsigned long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $96, %%rax\n"
			"syscall" : : "g"(tv), "g"(tz));
	return (int)ret;
}

int maya_sigaction(unsigned int sig, struct sigaction *act, struct sigaction *oldact)
{
	unsigned long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $13, %%rax\n"
			"syscall" : : "g"(sig), "g"(act), "g"(oldact));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;

}

long _lseek(long fd, long offset, unsigned int whence)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $8, %%rax\n"
                        "syscall" : : "g"(fd), "g"(offset), "g"(whence));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;

}

int _getpid(void)
{
        long ret;
        __asm__ volatile(
                        "mov $39, %%rax\n"
                        "syscall\n"
                        "mov %%rax, %0" : "=g"(ret));
        return (int)ret;
}

int _getppid(void)
{
	long ret;
	__asm__ volatile(
			"mov $110, %%rax\n"
			"syscall\n" 
			"mov %%rax, %0" : "=g"(ret));
	return (int)ret;
}
	
void _pause(void)
{
	__asm__ volatile(
			"mov $34, %rax\n"
			"syscall");

}

int _wait4(long pid, long *ptr, long options, long *usage)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $61, %%rax\n"
			"syscall" : : "g"(pid), "g"(ptr), "g"(options), "g"(usage));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int) ret;

}

/*
 * Notice the (uint64_t) casts in the register constraints
 * if we don't have these, then we can't compile this code
 * with optimization because it tries to use 32bit registers
 * and fails to compile saying that mov is an illegal instruction.
 * this is a good lesson to note since I chased this for an hour.
 */
int _clone(unsigned long entry, unsigned long stack, unsigned int flags, long fd)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $56, %%rax\n" 
			"syscall\n"  ::  "g"((uint64_t)entry), "g"((uint64_t)stack), "g"((uint64_t)flags), "g"((uint64_t)fd));

	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

int _prctl(long option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long ret;
	
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $157, %%rax\n"
			"syscall\n" :: "g"(option), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

int create_thread(void (*fn)(void *), void *data)
{
        long retval;
        void **newstack;
	unsigned int fnAddr = (unsigned int)(uintptr_t)fn;
	fn = (void (*)(void *))((uintptr_t)fnAddr & ~(uint32_t)0x0);
	
        newstack = (void **)createStack();
        *--newstack = data;
        
        __asm__ __volatile__(
                "syscall        \n\t"
                "test %0,%0     \n\t"        /* check return value */
                "jne 1f         \n\t"            /* jump if parent */
                "call *%3       \n\t"          /* start subthread function */
                "mov %2,%0      \n\t"
                "xor %%r10, %%r10\n\t"
                "xor %%r8, %%r8\n\t"
                "xor %%r9, %%r9 \n\t"
                "int $0x80      \n\t"           /* exit system call: exit subthread */
                "1:\t"
                :"=a" (retval)
                :"0" (__NR_clone),"i" (__NR_exit),
                 "g" (fn),
                 "D" (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_UNTRACED| SIGCHLD),
                 "S" (newstack));

        if (retval < 0) {
                errno = -retval;
                retval = -1;
        }
        return retval;
}


int _read(long fd, char *buf, unsigned long len)
{
	 long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $0, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

long _write(long fd, char *buf, unsigned long len)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $1, %%rax\n"
			"syscall" : : "g"(fd), "g"(buf), "g"(len));
	asm("mov %%rax, %0" : "=r"(ret));
	return ret;
}

int _fstat(long fd, void *buf)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"syscall" : : "g"(fd), "g"(buf));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

long _kill(unsigned int pid, unsigned int sig)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $62, %%rax\n"
			"syscall" : : "g"(pid), "g"(sig));
	asm ("mov %%rax, %0" : "=r"(ret));
}

long _open(char *path, unsigned long flags)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $2, %%rax\n"
			"syscall" : : "g"(path), "g"(flags));
	asm ("mov %%rax, %0" : "=r"(ret));		
	
	return ret;
}

int _close(unsigned int fd)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov $3, %%rax\n"
			"syscall" : : "g"(fd));
	return (int)ret;
}

long maya_ptrace(long request, long pid, void *addr, void *data)
{
	long ret;

	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $101, %%rax\n"
			"syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
	asm("mov %%rax, %0" : "=r"(ret));
	
	return ret;
}

int _mprotect(void * addr, unsigned long len, int prot)
{
	unsigned long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $10, %%rax\n"
			"syscall" : : "g"(addr), "g"(len), "g"(prot));
	asm("mov %%rax, %0" : "=r"(ret));
	
	return (int)ret;
}

void *_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
	long mmap_fd = fd;
	unsigned long mmap_off = off;
	unsigned long mmap_flags = flags;
	unsigned long ret;

	__asm__ volatile(
			 "mov %0, %%rdi\n"
			 "mov %1, %%rsi\n"
			 "mov %2, %%rdx\n"
			 "mov %3, %%r10\n"
			 "mov %4, %%r8\n"
			 "mov %5, %%r9\n"
			 "mov $9, %%rax\n"
			 "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
	asm ("mov %%rax, %0" : "=r"(ret));		
	return (void *)ret;
}

int _modify_ldt(long func, void *ptr, unsigned long bytecount)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $154, %%rax\n"
			"syscall\n" : : "g"(func), "g"(ptr), "g"(bytecount));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}


void Exit(long status)
{
	__asm__ volatile("mov %0, %%rdi\n"
			 "mov $60, %%rax\n"
		 	 "syscall" : : "r"(status));
}

void exit_thread(void)
{
	Exit(0);
}

/*
 * Return instruction pointer
 */
unsigned long get_rip(void)
{
  	asm(
	  "call get_ip   \n"
          ".globl get_ip \n"
          "get_ip:	\n"
          "pop %rax"
	);
}

static __inline void swap_bytes(unsigned char *a, unsigned char *b)
{
    unsigned char temp;

    temp = *a;
    *a = *b;
    *b = temp;
}



#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

static void salsa20_wordtobyte(u8 output[64],const u32 input[16])
{
  u32 x[16];
  int i;

  for (i = 0;i < 16;++i) x[i] = input[i];
  for (i = 20;i > 0;i -= 2) {
    x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 0],x[12]), 7));
    x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[ 4],x[ 0]), 9));
    x[12] = XOR(x[12],ROTATE(PLUS(x[ 8],x[ 4]),13));
    x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[12],x[ 8]),18));
    x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 5],x[ 1]), 7));
    x[13] = XOR(x[13],ROTATE(PLUS(x[ 9],x[ 5]), 9));
    x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[13],x[ 9]),13));
    x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 1],x[13]),18));
    x[14] = XOR(x[14],ROTATE(PLUS(x[10],x[ 6]), 7));
    x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[14],x[10]), 9));
    x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 2],x[14]),13));
    x[10] = XOR(x[10],ROTATE(PLUS(x[ 6],x[ 2]),18));
    x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[15],x[11]), 7));
    x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 3],x[15]), 9));
    x[11] = XOR(x[11],ROTATE(PLUS(x[ 7],x[ 3]),13));
    x[15] = XOR(x[15],ROTATE(PLUS(x[11],x[ 7]),18));
    x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[ 0],x[ 3]), 7));
    x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[ 1],x[ 0]), 9));
    x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[ 2],x[ 1]),13));
    x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[ 3],x[ 2]),18));
    x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 5],x[ 4]), 7));
    x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 6],x[ 5]), 9));
    x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 7],x[ 6]),13));
    x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 4],x[ 7]),18));
    x[11] = XOR(x[11],ROTATE(PLUS(x[10],x[ 9]), 7));
    x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[11],x[10]), 9));
    x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 8],x[11]),13));
    x[10] = XOR(x[10],ROTATE(PLUS(x[ 9],x[ 8]),18));
    x[12] = XOR(x[12],ROTATE(PLUS(x[15],x[14]), 7));
    x[13] = XOR(x[13],ROTATE(PLUS(x[12],x[15]), 9));
    x[14] = XOR(x[14],ROTATE(PLUS(x[13],x[12]),13));
    x[15] = XOR(x[15],ROTATE(PLUS(x[14],x[13]),18));
  }
  for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

void ECRYPT_init(void)
{
  return;
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void ECRYPT_keysetup(ECRYPT_ctx *x,const u8 *k,u32 kbits,u32 ivbits)
{
  int i;
  static const char *constants;

  x->input[1] = U8TO32_LITTLE(k + 0);
  x->input[2] = U8TO32_LITTLE(k + 4);
  x->input[3] = U8TO32_LITTLE(k + 8);
  x->input[4] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[11] = U8TO32_LITTLE(k + 0);
  x->input[12] = U8TO32_LITTLE(k + 4);
  x->input[13] = U8TO32_LITTLE(k + 8);
  x->input[14] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[5] = U8TO32_LITTLE(constants + 4);
  x->input[10] = U8TO32_LITTLE(constants + 8);
  x->input[15] = U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x,const u8 *iv)
{
  x->input[6] = U8TO32_LITTLE(iv + 0);
  x->input[7] = U8TO32_LITTLE(iv + 4);
  x->input[8] = 0;
  x->input[9] = 0;
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  u8 output[64];
  int i;

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte(output,x->input);
    x->input[8] = PLUSONE(x->input[8]);
    if (!x->input[8]) {
      x->input[9] = PLUSONE(x->input[9]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

void ECRYPT_decrypt_bytes(ECRYPT_ctx *x,const u8 *c,u8 *m,u32 bytes)
{
  ECRYPT_encrypt_bytes(x,c,m,bytes);
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x,u8 *stream,u32 bytes)
{
  u32 i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  ECRYPT_encrypt_bytes(x,stream,stream,bytes);
}

static inline void opaque_jmp_1(void)
{
	__asm__ volatile ("xor %eax, %eax\n"
			  "jne 0x4c");
}

static inline void opaque_jmp_2(void)
{
	__asm__ volatile("xorl %edx, %edx\n"
			 "cmp $0, %edx\n"
			 "jne 0x1f");
}

static inline void opaque_jmp_3(void)
{
	__asm__ volatile("xor %ecx, %ecx\n"
			 "test %ecx, %ecx\n"
			 "jne 0x3d");
}


