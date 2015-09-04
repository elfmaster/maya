#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <errno.h>
#include "udis86/udis86.h"
#include "shared_data.h"

#define WHITE "\x1B[37m"
#define RED  "\x1B[31m"
#define GREEN  "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define DEFAULT_COLOR  "\x1B[0m"

#define MAX_SECTIONS 64
#define MAX_KEYSIZE 32

#define MAYA_L0_PROT 0 //no protection
#define MAYA_L1_PROT 1 //function runtime layer
#define MAYA_L2_PROT 2 //function runtime layer + code and data
#define MAYA_L3_PROT 3 //function runtime layer + code and data + whole elf encryption

#define SPEC_FAILED 1
#define SPEC_PASSED 0

#define META_XOR_BITS 0xf3c9d12

#define RANDOM_STRING_COUNT 30

#define MAX_LIBS 64

#define FCALL_INTERVAL(x) ((x / 10) * 3) // Interval of function calls before it is re-encrypted

maya_cflow_t maya_cflow[MAX_CFLOW_ITEMS];
uint8_t fingerprint[FINGERPRINT_SIZE];


struct fde_func_data { /* For eh_frame.c */ 
        uint64_t addr;
        size_t size;
};
       

struct {
	int nosymtab;
	int speedext;
	int skipverify;
	int randsym;
	int sections;
	int customkey;
	int fingerprint;
	int strip;
	int verbose;
	int layers;
	int l3;
	int cflow;
	int obfuscate;
	int nanomites;
	int cflow_profile;
	int ro_relocs;
} opts;

struct shared_libraries {
	char *name;
	char *path;
};

struct brain_symbols {
	struct {
		uint32_t knowledge;
		uint32_t mayaModes;
		uint32_t mayaCflow;
		uint32_t functionSizes;
		uint32_t fingerprint;
		uint32_t verify_fingerprint;
		uint32_t trace_thread;
	} sizes;
	Elf64_Addr knowledge; //struct
	Elf64_Addr hostEntry; //long
	Elf64_Addr mayaModes; //struct
	Elf64_Addr mayaCflow; //struct
	Elf64_Addr functionSizes; //struct
	Elf64_Addr fingerprint; //function
	Elf64_Addr verify_fingerprint; //function
	Elf64_Addr trace_thread; //function
};

typedef struct {
	uint32_t branch_target;
	uint32_t retaddr;
} emulate_t;

typedef struct {
        uint64_t offset;
	uint64_t vaddr;
	uint32_t call_target;
        size_t len;
        const char *string;
	const uint8_t *hexbytes;
	int ret;
	int jmp;
	int call;
	int nanomite;
	enum ud_mnemonic_code mnemonic;
	emulate_t emulate;
} instdata_t;

typedef struct {
	instdata_t *instdata;
	unsigned int instcount;
	size_t maxsize;
} codemap_t;
	

struct profile_list {
	struct profile_list *next;
	struct {
		char *name; // function name
		uint32_t vaddr;
		uint32_t size; // function size in bytes
		uint32_t callcount; // how many times is it called?
		uint32_t retcount; // how many ret instructions
		uint64_t *retlocation; //address of where ret instruction is
	} func;
	
	struct {
		int tailcall; // tailcall optimization present?
		int interval; // how may call intervals before re-encrypt?
		int multiret; // multiple ret instructions
	} prof;
};

typedef struct {
	struct profile_list *list_head;
	uint32_t items;
} cprofile_t;
	

typedef struct {
	int eh_frame;
	int exec_type;
	int mach_type;
	int shdr_table;
	int shdr_count;
	int text_perms;
	int phdr_align;
	int pt_load;
	int symtab;
} elfspec_t;

typedef struct {
	size_t len;
	unsigned int location;
} stub_meta_t;

typedef struct {
	uint8_t *mem;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Off textOff;
	Elf64_Off dataOff;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	Elf64_Addr entryPoint; // various interpretations throughout Elf loading/protecting
	Elf64_Addr origEntry;
	Elf64_Addr cflow_count;
	struct brain_symbols brainsymbol;
	unsigned int origTextSize;
	unsigned int origDataSize;
	unsigned int interpSize;
	uint8_t **sections;
	uint8_t type;
	unsigned int size;
	unsigned int mmap_flags;
	unsigned int mmap_prot;
	char *path;
	char *StringTable;
	unsigned int crypt_item_count;
	struct stat st;
	/*
	 * Which sections to encrypt  
	 */
	char *sectionNames[MAX_SECTIONS];
	int sectionCount;
	/* nanomites */
	nanomite_t *nanomites;
	unsigned int nanocount;
	codemap_t *codemap; //codemap ptr;
	
	cprofile_t cprofile;
	uint32_t fcount;
	/* Used by the 3rd layer stub */
	struct shared_libraries libs[MAX_LIBS];
	Elf64_Dyn *dyn;
	unsigned int libcount;
	unsigned int textSize;
	unsigned int dataSize;
	unsigned int bssVaddr;
	unsigned int bssSize;
	char *linker_path;
	
} ElfBin_t;



/* crypto.c */
void rc4_crypt(unsigned char *key, unsigned char *text, unsigned int textlength);
void generate_random_key(uint8_t *key);

	
/* main.c */
int ExtractArgs(char ***argvp, char *delim, char *s);

/* elf.c */
int build_protection_info(ElfBin_t *target, cryptMetaData_t **cData);
void list_protection_info(cryptMetaData_t *cData, unsigned int count);
int apply_code_obfuscation(ElfBin_t *, ElfBin_t *);
int get_strtbl_offset(char *p, char *string, int count);
int randomize_syms(ElfBin_t *bin);
int randomize_shdrs(ElfBin_t *bin);
int isElf(const char *path);
int reloadElf(ElfBin_t *bin);
void unloadElf(ElfBin_t *bin);
int loadElf(const char *path, ElfBin_t *bin, int prot, int flags);
void inject_tracer_code(unsigned int psize, ElfBin_t *exe, ElfBin_t *rel, Elf64_Addr entry_point);
int injectObject(ElfBin_t *rel, ElfBin_t *exe);
void fixup_tracer_code(ElfBin_t *, ElfBin_t *);
int RelocateCode(ElfBin_t *, ElfBin_t *);
Elf64_Off get_section_offset(ElfBin_t *, char *);
unsigned int get_section_size(ElfBin_t *, char *);
unsigned int get_section_vaddr(ElfBin_t *, char *);
Elf64_Addr GetSymAddr(const char *, ElfBin_t *);
unsigned int get_symbol_size_by_addr(ElfBin_t *, Elf64_Addr);
int in_range_by_section(ElfBin_t *target, char *section, Elf64_Addr addr);
int phdr_is_valid(ElfBin_t *, int);

/* cflow.c */
int generate_local_cflow_data(ElfBin_t *exe, maya_cflow_t *cflow);


/* fp.c */
int generate_fingerprint(uint8_t *);

/* checker.c */
int check_elf64_integrity(ElfBin_t *elf, elfspec_t *specs);
int verify_elf_requirements(ElfBin_t *elf);

/* disas.c */
int generate_code_map(codemap_t *map, ElfBin_t *bin);

/* profile.c */
uint32_t construct_code_profile(ElfBin_t *, codemap_t *, cprofile_t *);


/* eh_frame.c */
//size_t get_all_functions(const char *, struct fde_func_data **);
