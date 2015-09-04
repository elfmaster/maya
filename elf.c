#include "maya.h"

#define TMP ".maya.tmp.zyZ"

#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE) 

#define JMPCODE_LEN 6

#define MAIN_FUNCTION_PADDING_SIZE 4
/*
 * Offsets into struct knowledge (Within mayas tracer.o code)
 * In the future it would be wise to use dwarf2 to automated
 * this process and not have to work off of static offsets which
 * must always be adjusted by hand during development
 */
#define KNOWLEDGE_HOST_ENTRY_OFFSET 0
#define KNOWLEDGE_CRYPTINFO_TEXT_OFFSET 8
#define KNOWLEDGE_CRYPTINFO_DATA_OFFSET (8 + sizeof(cryptInfo_t))
#define KNOWLEDGE_CRYPTINFO_RODATA_OFFSET (8 + sizeof(cryptInfo_t) * 2)
#define KNOWLEDGE_CRYPTINFO_PLT_OFFSET (8 + sizeof(cryptInfo_t) * 3)
#define KNOWLEDGE_FINGERPRINT_OFFSET (8 + (sizeof(cryptInfo_t) * 4))
#define KNOWLEDGE_CRYPT_ITEM_COUNT_OFFSET (8 + FINGERPRINT_SIZE + (sizeof(cryptInfo_t) * 4))
#define KNOWLEDGE_CFLOW_ITEM_COUNT_OFFSET (8 + FINGERPRINT_SIZE + sizeof(unsigned int) + (sizeof(cryptInfo_t) * 4))
#define KNOWLEDGE_RO_RELOCS_OFFSET (8 + FINGERPRINT_SIZE + (sizeof(unsigned int) * 2) + (sizeof(cryptInfo_t) * 4))
#define KNOWLEDGE_CRYPTLOC_OFFSET (8 + ((sizeof(unsigned int) * 2)) + FINGERPRINT_SIZE + (sizeof(cryptInfo_t) * 4) + sizeof(ro_relocs_t))
#define KNOWLEDGE_NANOMITE_OFFSET (8 + ((sizeof(unsigned int) * 2)) + FINGERPRINT_SIZE + (sizeof(cryptInfo_t) * 4) + sizeof(ro_relocs_t) + (sizeof(cryptMetaData_t) * MAX_CRYPT_POCKETS))

#define KNOWLEDGE_SIZE 41216 /* The size of knowledge_t struct within tracer.o */


#define FSIZES_TRACE_THREAD_OFFSET 0
#define FSIZES_FINGERPRINT_OFFSET 4
#define FSIZES_VALIDATE_FINGERPRINT_OFFSET 8
/*
 * Not all of maya's knowledge is stored in knowledge_t struct, but
 * eventually for the sake of good engineering it should be. Meanwhile
 * we have maya_modes_t and maya_cflow_t structs as well.
 */

/* maya_modes_t maya_mode is declared in main.c
 */


/*
 * Can randomize up to this many symbols
 * unlikely that an executable would have
 * have this many object and function symbols
 * combined.
 */
#define MAX_SYM_COUNT 65535

struct section_type 
{
        char *name;
        uint32_t type;
        int flags;
};

#define MAX_SHDR_TYPES 28
#define SHT_VERSYM 0x6fffffff
#define SHT_VERNEED 0x6ffffffe

#define W 1      /* SHF_WRITE */
#define A 2      /* SHF_ALLOC */
#define X 4      /* SHF_EXECINSTR */

struct section_type section_type[] = {
{".interp",     SHT_PROGBITS,   A },
{".hash",       SHT_HASH,       A },
{".note.ABI-tag", SHT_NOTE,     A },
{".gnu.hash",   SHT_GNU_HASH,   A },
{".dynsym",     SHT_DYNSYM,     A },
{".dynstr",     SHT_STRTAB,     A },
{".gnu.version",SHT_VERSYM,     A },
{".gnu.version_r",SHT_VERNEED,  A },
{".rel.dyn",    SHT_REL,        A },
{".rel.plt",    SHT_REL,        A },
{".init",       SHT_PROGBITS,   A|X},
{".plt",        SHT_PROGBITS,   A|X},
{".text",       SHT_PROGBITS,   A|X},
{".fini",       SHT_PROGBITS,   A|X},
{".rodata",     SHT_PROGBITS,   A },
{".eh_frame_hdr",SHT_PROGBITS,  A },
{".eh_frame",   SHT_PROGBITS,   A },
{".ctors",      SHT_PROGBITS,   W|A},
{".dtors",      SHT_PROGBITS,   W|A},
{".jcr",        SHT_PROGBITS,   W|A},
{".dynamic",    SHT_DYNAMIC,    W|A},
{".got",        SHT_PROGBITS,   W|A},
{".got.plt",    SHT_PROGBITS,   W|A},
{".data",       SHT_PROGBITS,   W|A},
{".bss",        SHT_NOBITS,     W|A},
{".shstrtab",   SHT_STRTAB,     0 },
{".symtab",     SHT_SYMTAB,     0 },
{".strtab",     SHT_STRTAB,     0 },
{"",    SHT_NULL}
};

struct symVaddrs {
	unsigned long vaddr;	
	char *name;
};

/* Globals */
cryptInfo_t cryptinfo_text, cryptinfo_data, cryptinfo_rodata, cryptinfo_plt, cryptinfo_knowledge;

struct {
	unsigned int section_size;
	unsigned int section_offset;
	unsigned int section_vaddr;
} text, data, rodata, plt, knowledge;

/* 
 * Info for read-only relocs
 */
ro_relocs_t ro_relocs;

char *randomStrings[] = {"nietzche", "designs", "infinite", "lysergic", "elixir", "deterministic", "godsVengence", "florid", "fecundate"  
                         "el8", "phrack", "faery", "rimbaud", "flex_capacitor", "del0rion", "robotic_thang", "mystified", "listlinker",   
                         "byteswap_and_giggle", "little_indian", "big_ass_indian", "enchanted_serializer", "marionette", "mindfucker",    
                         "mind_control", "illuminati_shake_and_shiver", "extraterrestrial", "violent_overthrow", "rev0lut10n", "freedoM_fighterz", NULL };

extern maya_modes_t maya_mode;

int check_symtab(ElfBin_t *target)
{
	Elf64_Shdr *shdr = target->shdr;
	char *StringTable = &target->mem[shdr[target->ehdr->e_shstrndx].sh_offset];
	int i;

	for (i = 0; i < target->ehdr->e_shnum; i++) {
		if (!strcmp((char *)&StringTable[shdr[i].sh_name], ".symtab")) {
			return 1;
		}
	}
	return 0;
}

Elf64_Addr get_offset_of_section(ElfBin_t *target, const char *name)
{
	Elf64_Ehdr *ehdr = target->ehdr;
	Elf64_Shdr *shdr = target->shdr;
	
	char *StringTable = (char *)&target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
	int i;

	for (i = 0; i < ehdr->e_shnum; i++) 
		if (strcmp(&StringTable[shdr[i].sh_name], name) == 0) 
			return shdr[i].sh_offset;	

	return 0;

}

Elf64_Addr get_size_of_section(ElfBin_t *target, const char *name)
{
        Elf64_Ehdr *ehdr = target->ehdr;
        Elf64_Shdr *shdr = target->shdr;

        char *StringTable = (char *)&target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
        int i;

        for (i = 0; i < ehdr->e_shnum; i++)
                if (strcmp(&StringTable[shdr[i].sh_name], name) == 0)
                        return shdr[i].sh_size;

        return 0;

}

int in_range_by_section(ElfBin_t *target, char *section, Elf64_Addr addr)
{	
	Elf64_Ehdr *ehdr = target->ehdr;
	Elf64_Shdr *shdr = target->shdr;

	char *StringTable = (char *)&target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
	int i;
	
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (strcmp(&StringTable[shdr[i].sh_name], section) == 0) {
			if (addr >= shdr[i].sh_addr && addr < shdr[i].sh_addr + shdr[i].sh_size)
				return 1;
		}
	}
	/* addr is not in the specified sections range */
	return 0;
}
unsigned int get_symbol_size_by_addr(ElfBin_t *target, Elf64_Addr addr)
{
	Elf64_Sym *symtab;
	int i, j, symcount;
	
	for (i = 0; i < target->ehdr->e_shnum; i++) {
		if(target->shdr[i].sh_type == SHT_SYMTAB) {
			symtab = (Elf64_Sym *)&target->mem[target->shdr[i].sh_offset];
			for (j = 0; j < target->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
				if (symtab->st_value == addr)
					return symtab->st_size;
			}
		}
	}
	return 0;
}

uint32_t GetSymSize(const char *name, ElfBin_t *target)
{
	Elf64_Sym *symtab;
        char *SymStrTable;
        int i, j, symcount;

        for (i = 0; i < target->ehdr->e_shnum; i++)
                if (target->shdr[i].sh_type == SHT_SYMTAB || target->shdr[i].sh_type == SHT_DYNSYM) {
                        SymStrTable = (char *)&target->mem[target->shdr[target->shdr[i].sh_link].sh_offset];
                        symtab = (Elf64_Sym *)&target->mem[target->shdr[i].sh_offset];

                        for (j = 0; j < target->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
                                if(strcmp(&SymStrTable[symtab->st_name], name) == 0)
                                        return (symtab->st_size);
                        }
                }
        return 0;

}
Elf64_Addr GetSymAddr(const char *name, ElfBin_t *target)
{
        Elf64_Sym *symtab;
        char *SymStrTable;
        int i, j, symcount;

        for (i = 0; i < target->ehdr->e_shnum; i++)     
                if (target->shdr[i].sh_type == SHT_SYMTAB || target->shdr[i].sh_type == SHT_DYNSYM) {
			SymStrTable = (char *)&target->mem[target->shdr[target->shdr[i].sh_link].sh_offset];
			symtab = (Elf64_Sym *)&target->mem[target->shdr[i].sh_offset];
			
                        for (j = 0; j < target->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
                                if(strcmp(&SymStrTable[symtab->st_name], name) == 0)
                                        return (symtab->st_value);
                        }
                }
        return 0;
}

Elf64_Off get_section_offset(ElfBin_t *target, char *name)
{
        char *StringTable = (char *)&target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
        int i;

        for (i = 0; i < target->ehdr->e_shnum; i++) {
                if (!strcmp(&StringTable[target->shdr[i].sh_name], name)) {
                        return target->shdr[i].sh_offset;
                }
        }
        return 0;
}

char * get_section_name(ElfBin_t *target, Elf64_Addr vaddr)
{
	char *StringTable = (char *)&target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
	int i;
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (vaddr >= target->shdr[i].sh_addr && vaddr < target->shdr[i].sh_addr + target->shdr[i].sh_size)
			return (char *)xstrdup(&StringTable[target->shdr[i].sh_name]);
	return (char *)xstrdup("unknown");
}

unsigned int get_section_size(ElfBin_t *target, char *name)
{
	char *StringTable = (char *)&target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
        int i;
        for (i = 0; i < target->ehdr->e_shnum; i++) {
                if (!strcmp(&StringTable[target->shdr[i].sh_name], name)) {
                        return target->shdr[i].sh_size;
                }
        }
        return 0;
}

unsigned int get_section_vaddr(ElfBin_t *target, char *name)
{
 	char *StringTable = (char *)&target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
        int i;

        for (i = 0; i < target->ehdr->e_shnum; i++) {
                if (!strcmp(&StringTable[target->shdr[i].sh_name], name)) {
                       return target->shdr[i].sh_addr;
                }

        }
        return 0;
}

int isElf(const char *path)
{
	int fd;
	uint8_t *mem;

	if ((fd = open(path, O_RDONLY)) < 0) {
		perror("open");
		exit(-1);
	}
	
	mem = mmap(NULL, 64, PROT_READ, MAP_PRIVATE, fd, 0);
	
	if (mem[0] != 0x7f && strcmp(&mem[1], "ELF")) 
		return 0;
	
	return 1;
}

int reloadElf(ElfBin_t *bin)
{
	char *path = strdup(bin->path);
	unsigned int size = bin->size;
	unsigned int flags = bin->mmap_flags;
	unsigned int prot = bin->mmap_prot;

	unloadElf(bin);
	if (loadElf(path, bin, prot, flags) < 0)
		return -1;
	
	free(path);
	return 0;

}

void unloadElf(ElfBin_t *bin)
{
	free(bin->path);
	munmap(bin->mem, bin->size);
}

/*
 * Protection locations: Currently this function rely's on
 * the symbol table to get function locations. This is not
 * preferable and should be changed to utilize more advanced
 * heuristics, as many binaries won't contain symbols for local
 * functions.
 */

int build_protection_info(ElfBin_t *target, cryptMetaData_t **cData)
{
  	Elf64_Sym *symtab;
        char *SymStrTable;
        unsigned int i, j, k, l, symcount = 0;
	cryptMetaData_t *cp;
	struct timeval tv;
	struct profile_list *cprofile = (struct profile_list *)&target->cprofile.list_head; // code profile
	struct profile_list *current;
	unsigned int fcount = 0;

	
	if (opts.nosymtab) {
		printf("[!] No symbol table present; using only the dwarf .eh_frame data to construct code level encryption\n");
		*cData = (cryptMetaData_t *)malloc(sizeof(cryptMetaData_t) * target->cprofile.items);
		for (current = cprofile; current != NULL; current = current->next) {
	
			if (current->func.vaddr == 0) //workaround for buggy code 
				continue;
			
			/*
		         * We don't want to set a breakpoint in the actual PLT sections or encrypt them
			 */
			if (in_range_by_section(target, ".plt", current->func.vaddr))
				continue;

			/*
			 * ignore _start
	 		 */
			if (current->func.vaddr == target->origEntry)
				continue;

			(*cData)[fcount].size = current->func.size;
			(*cData)[fcount].startVaddr = current->func.vaddr;
			(*cData)[fcount].endVaddr = current->func.vaddr + current->func.size - 1;
			strncpy((*cData)[fcount].symname, current->func.name, MAX_SYMNAM_LEN);
			(*cData)[fcount].symname[MAX_SYMNAM_LEN - 1] = '\0';
			(*cData)[fcount].origByte = target->mem[current->func.vaddr - target->textVaddr];
		        for (k = 0; k < MAX_KEY_LEN; k++) {
                        	gettimeofday(&tv, NULL);
                                srand(tv.tv_usec);
                                (*cData)[fcount].key[k] = target->mem[rand() % target->size] ^ (k + (rand() % 'Z'));
                        }

			for (k = 0; k < target->codemap->instcount; k++) {
                        	if ((*cData)[fcount].startVaddr == target->codemap->instdata[k].vaddr) {
                                	for (l = 0; l < (*cData)[fcount].size; l++) {
                                        	if (target->codemap->instdata[k + l].ret)
                                                	(*cData)[fcount].isRet++;
                                                if (target->codemap->instdata[k + l].vaddr > (*cData)[fcount].endVaddr)
                                                	break;
                                        }
                                }
			}
			fcount++;	
		}
		return fcount;
	}

	/*
 	 * If we made it here then an ELF .symtab exists and Maya will use that to create
	 * the code protection.
	 */

        for (i = 0; i < target->ehdr->e_shnum; i++) {
                if (target->shdr[i].sh_type == SHT_SYMTAB) {
		
			*cData = (cryptMetaData_t *)malloc(sizeof(cryptMetaData_t) * ((target->shdr[i].sh_size / sizeof(Elf64_Sym)) + 1));
                        SymStrTable = (char *)&target->mem[target->shdr[target->shdr[i].sh_link].sh_offset];
                        symtab = (Elf64_Sym *)&target->mem[target->shdr[i].sh_offset];
		
			for (j = 0; j < target->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
				if (ELF64_ST_TYPE(symtab->st_info) != STT_FUNC)
					continue;
				if (ELF64_ST_BIND(symtab->st_info) == STB_WEAK)
					continue;
				if (symtab->st_other == STV_HIDDEN)
					continue;
				if (symtab->st_value == 0)
					continue;
				/* 
				 * Get data about per-function encryption/protection
				 */
				(*cData)[symcount].size = symtab->st_size;
				(*cData)[symcount].startVaddr = symtab->st_value;
				(*cData)[symcount].endVaddr = (*cData)[symcount].startVaddr + (*cData)[symcount].size - 1;
				strncpy((*cData)[symcount].symname, (char *)&SymStrTable[symtab->st_name], MAX_SYMNAM_LEN);
				(*cData)[symcount].symname[MAX_SYMNAM_LEN - 1] = '\0';
				if (!strcmp((*cData)[symcount].symname, "main"))
					(*cData)[symcount].size += MAIN_FUNCTION_PADDING_SIZE;
				(*cData)[symcount].origByte = target->mem[symtab->st_value - target->textVaddr];
				for (k = 0; k < MAX_KEY_LEN; k++) { 
					gettimeofday(&tv, NULL);
					srand(tv.tv_usec);
					(*cData)[symcount].key[k] = target->mem[rand() % target->size] ^ (k + (rand() % 'Z'));	
				}
				/*
				 * Is there a 'ret' instruction at the end of the function?
				 */
				for (k = 0; k < target->codemap->instcount; k++)
					if ((*cData)[symcount].startVaddr == target->codemap->instdata[k].vaddr) {
						for (l = 0; l < (*cData)[symcount].size; l++) {
							if (target->codemap->instdata[k + l].ret) 
								(*cData)[symcount].isRet++;
							if (target->codemap->instdata[k + l].vaddr > (*cData)[symcount].endVaddr)
								break;
						}
					}
								

				/*
				 * Fill out fn_personality (ret locations, and mutation interval
	 			 */
				if (opts.cflow_profile) {
			 		for (k = 0; k < target->codemap->instcount; k++)
						if ((*cData)[symcount].startVaddr == target->codemap->instdata[k].vaddr) {
							for (current = cprofile; current; current = current->next) {
								if (current->func.vaddr == target->codemap->instdata[k].vaddr) {
									(*cData)[symcount].retcount = current->func.retcount;
									for (l = 0; l < (*cData)[symcount].retcount; l++) {
										(*cData)[symcount].fn_personality.retinstr[l].retOffset =
										  current->func.retlocation[l] - current->func.vaddr;
										if (opts.verbose)
											printf("ret offset for fn %s: %x\n", (*cData)[symcount].symname,
												(*cData)[symcount].fn_personality.retinstr[l].retOffset);
										(*cData)[symcount].fn_personality.retinstr[l].origByte = 0xC3;
									}
									printf("prof interval: %d\n", current->prof.interval);
									(*cData)[symcount].fn_personality.mutation_interval = 
										(current->prof.interval == 0) ? 1 : current->prof.interval;
								}
							}
						}
					}
																
				symcount++;
			}
		}
	}
	
	return symcount;
}

/*
 * This gets ran before tracer.o (rel) is injected into host (target).
 * This function is not called if no protection layers are added.
 */
int apply_code_obfuscation(ElfBin_t *target, ElfBin_t *rel)
{
	unsigned int pc;
	cryptMetaData_t *cData;
	uint8_t *mp;
	uint32_t *tp, trap;
	int i, j, bc, k, l;
	
	crypto_t crypto;
	unsigned int knowledgeOffset;
	unsigned int cryptOffset;
	
	codemap_t *map = target->codemap;
	nanomite_t *nanomites = target->nanomites;

	pc = build_protection_info(target, &cData);
	if (pc == 0) {
		printf("[!] Unable to build code level protection without ELF symbol table (Not yet supported)\n");
		return -1;
	}
	
	target->crypt_item_count = pc;
	list_protection_info(cData, pc);
	
	knowledgeOffset = rel->brainsymbol.hostEntry; //GetSymAddr("knowledge", rel);
	cryptOffset = knowledgeOffset + KNOWLEDGE_CRYPTLOC_OFFSET;
		
	printf("[+] Applying function level code encryption:simple stream cipher (1st Layer)\n");
	for (i = 0; i < pc; i++) {
		memcpy((uint8_t *)&rel->mem[cryptOffset + (i * sizeof(cryptMetaData_t))], 
			(uint8_t *)&cData[i], sizeof(cryptMetaData_t));
	}
	mp = &target->mem[0];
	for (i = 0; i < pc; i++) {
		if (cData[i].isRet == 0)
			continue;
		mp = &target->mem[cData[i].startVaddr - target->textVaddr];
		for (bc = 0, k = 0; k < cData[i].size; k++) {
			if (k == 0) {
				tp = (uint32_t *)&mp[0];
				trap = *tp;
				trap = (trap & ~0xFF) | 0xCC;
				*(uint32_t *)tp = trap;
				printf("Set trap at %x\n", cData[i].startVaddr);
				continue;
			}
			if (opts.nanomites) {
				for (j = 0; j < target->nanocount; j++) {
					if (cData[i].startVaddr + k == nanomites[j].site) {
						for (l = 0; l < nanomites[j].size; l++) {
							mp[l] = 0xCC;
						}
					}
				}
			}
			if (k == cData[i].size - 1) { 
				/* We use to place a 0xcc on the 'ret' */
				/* but we just let the runtime engine */
				/* do it now, this helps us deal with */
				/* cases where gcc optimizations fuck us */
			}

			mp[k] ^= cData[i].key[bc++];
			if (bc == MAX_KEY_LEN)
				bc = 0;
			
			
		}
	}
	
	if (opts.layers == MAYA_L2_PROT) {
		printf("\n[+] Applying host executable/data sections: SALSA20 streamcipher (2nd layer protection)\n\n");
	
		text.section_vaddr = get_section_vaddr(target, ".text");
		Elf64_Off textSectionOffset = text.section_offset = get_section_offset(target, ".text");
		unsigned int textSectionSize = text.section_size = get_section_size(target, ".text");
	
		
		printf("[+] Applying SALSA20 at original .text offset 0x%lx:  %d bytes long\n", textSectionOffset, textSectionSize);
		
		encrypt_stream(&crypto, (uint8_t *)&target->mem[textSectionOffset], textSectionSize, SALSA);
		memcpy(cryptinfo_text.key, crypto.key, MAX_KEY_LEN);
		memcpy(cryptinfo_text.iv, crypto.iv, MAX_IV_LEN);
		memcpy((ECRYPT_ctx *)&cryptinfo_text.ctx, (ECRYPT_ctx *)&crypto.ctx, sizeof(ECRYPT_ctx));
		cryptinfo_text.keylen = MAX_KEY_LEN;
		

		data.section_vaddr = get_section_vaddr(target, ".data");
		Elf64_Off dataSectionOffset = data.section_offset = get_section_offset(target, ".data");
		unsigned int dataSectionSize = data.section_size = get_section_size(target, ".data");
	
		printf("[+] Applying SALSA20 at original .data offset 0x%lx: %d bytes long\n", dataSectionOffset, dataSectionSize);
		
		encrypt_stream(&crypto, (uint8_t *)&target->mem[dataSectionOffset], dataSectionSize, SALSA);
		memcpy(cryptinfo_data.key, crypto.key, MAX_KEY_LEN);
		memcpy(cryptinfo_data.iv, crypto.iv, MAX_IV_LEN);
		memcpy((ECRYPT_ctx *)&cryptinfo_data.ctx, (ECRYPT_ctx *)&crypto.ctx, sizeof(ECRYPT_ctx));
		cryptinfo_data.keylen = MAX_KEY_LEN;
 
	
		rodata.section_vaddr = get_section_vaddr(target, ".rodata");
       	 	Elf64_Off rodataSectionOffset = rodata.section_offset = get_section_offset(target, ".rodata");
        	unsigned int rodataSectionSize = rodata.section_size = get_section_size(target, ".rodata");

        	printf("[+] Applying SALSA20 at original .rodata offset 0x%lx: %d bytes long\n", rodataSectionOffset, rodataSectionSize);
        	encrypt_stream(&crypto, (uint8_t *)&target->mem[rodataSectionOffset], rodataSectionSize, SALSA);
		memcpy(cryptinfo_rodata.key, crypto.key, MAX_KEY_LEN);
		memcpy(cryptinfo_rodata.iv, crypto.iv, MAX_IV_LEN);
		memcpy((ECRYPT_ctx *)&cryptinfo_rodata.ctx, (ECRYPT_ctx *)&crypto.ctx, sizeof(ECRYPT_ctx));
		cryptinfo_rodata.keylen = MAX_KEY_LEN;

	
		plt.section_vaddr = get_section_vaddr(target, ".plt");
        	Elf64_Off pltSectionOffset = plt.section_offset = get_section_offset(target, ".plt");
        	unsigned int pltSectionSize = plt.section_size = get_section_size(target, ".plt");

        	printf("[+] Applying SALSA20 at original .plt offset 0x%lx: %d bytes long\n", pltSectionOffset, pltSectionSize);
        	
		encrypt_stream(&crypto, (uint8_t *)&target->mem[pltSectionOffset], pltSectionSize, SALSA);
		memcpy(cryptinfo_plt.key, crypto.key, MAX_KEY_LEN);
		memcpy(cryptinfo_plt.iv, crypto.iv, MAX_KEY_LEN);
		memcpy((ECRYPT_ctx *)&cryptinfo_plt.ctx, (ECRYPT_ctx *)&crypto.ctx, sizeof(ECRYPT_ctx));
		cryptinfo_plt.keylen = MAX_KEY_LEN;


	}
	
}
	
	
void list_protection_info(cryptMetaData_t *cData, unsigned int count)
{
	int i, k;
	
	printf("[+] Function level decryption layer, (innermost layer), knowledge information:\n\n");
	for (i = 0; i < count; i++) {
		printf("%s :\t 0x%08lx :\t 0x%x : \t", cData[i].symname, cData[i].startVaddr, cData[i].size);
		for (k = 0; k < MAX_KEY_LEN; k++)
			printf("%02x", cData[i].key[k]);
		printf("\n");
	}
	printf("\n\n");
}


int get_strtbl_offset(char *p, char *string, int count)
{
        char *offset = p;
        while (count-- > 0)
        {
                while (*offset++ != '.')
			;	
                if (strcmp(string, offset-1) == 0)
                        return ((offset - 1) - p);
                /* some section names have two periods, thus messing us up */
                /* this will take care of that */
                if (!strncmp(offset-1, ".rel.", 5) || !strncmp(offset-1, ".gnu.", 5) 
                ||  !strncmp(offset-1, ".not.", 5) || !strncmp(offset-1, ".got.", 5))
                        while (*offset++ != '.');
                
        }
        return 0;
}

int get_sym_strtbl_offset(char *p, char *string, int count)
{
	char *offset = p;
        while (count-- > 0) {
                while (*offset++ != '\0')
                        ;
                if (strcmp(string, offset) == 0) {
                        return ((offset) - p);
		}
	}
	return 0;
}

void zero_string_tables(ElfBin_t *bin)
{
	int i, j;
	char *StringTable;
	char *origstbl = StringTable = (char *)&bin->mem[bin->shdr[bin->ehdr->e_shstrndx].sh_offset];
	
	for (i = 0; i < bin->shdr[bin->ehdr->e_shstrndx].sh_size; i++) {
		*StringTable = 0;
		StringTable++;
	}
	
	for (i = 0; i < bin->ehdr->e_shnum; i++) {
		if (bin->shdr[i].sh_type == SHT_SYMTAB) {
			StringTable = (char *)&bin->mem[bin->shdr[bin->shdr[i].sh_link].sh_offset];
			for (j = 0; j < bin->shdr[bin->shdr[i].sh_link].sh_size; j++) {
				*StringTable = 0;
				StringTable++;
			}
		}
		/*
		 else
		if (bin->shdr[i].sh_type == SHT_STRTAB) {	
			if (!strcmp((char *)&origstbl[bin->shdr[i].sh_name], ".dynstr"))
				continue;
			StringTable = (char *)&bin->mem[bin->shdr[i].sh_offset];
			for (j = 0; j < bin->shdr[i].sh_size; j++) {
				*StringTable = 0;
				StringTable++;
			}
		}	
		*/
		
	}
}

/*
 * Inject new symbol names 
 */

int inject_new_symbol_strings(ElfBin_t *bin)
{
	ElfBin_t *newbin = malloc(sizeof(ElfBin_t));
	Elf64_Sym *symtab;
	int string_count, i, j, new_size;
	char *NewStringTable;
	char *StringTable, *p;
	int fd;
	char null = 0;
	char *path = strdup(bin->path);

	for (i = 0; i < bin->ehdr->e_shnum; i++) 
		if (bin->shdr[i].sh_type == SHT_SYMTAB) {

			StringTable = (char *)&bin->mem[bin->shdr[bin->shdr[i].sh_link].sh_offset];
			string_count = bin->shdr[i].sh_size / sizeof(Elf64_Shdr);
        		NewStringTable = (char *)malloc(string_count * 16);
			
			/*
			 * We must extend the executable to create room for a potentially
			 * larger string table.
			 */
		    	if ((fd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, bin->st.st_mode)) == -1) {
                		perror("tmp binary: open");
                		exit(-1);
        		}
			
			write(fd, bin->mem, bin->size);
			write(fd, &null, string_count * 16);
			close(fd);

			int ret = loadElf(TMP, newbin, PROT_READ|PROT_WRITE, MAP_SHARED);
			if (ret < 0) {
				printf("LoadElf Failed: %s\n", strerror(errno));
				exit(-1);
			}

			if (string_count > RANDOM_STRING_COUNT)
				string_count = RANDOM_STRING_COUNT - 1;
	
			StringTable = (char *)&newbin->mem[newbin->shdr[bin->shdr[i].sh_link].sh_offset];
		
			for (p = NewStringTable + 1, i = 0; i < string_count; i++) {
                		strcpy(p, randomStrings[i]);
                		p += strlen(p) + 1;
                		*p = 0;
        		}
			symtab = (Elf64_Sym *)&newbin->mem[bin->shdr[i].sh_offset];
			for (j = 0; j < string_count; j++) {
				symtab->st_name = get_sym_strtbl_offset(NewStringTable, randomStrings[j], string_count);
				symtab++;
			}
			for (new_size = 0, j = 0; j < string_count; j++)
				new_size += strlen(randomStrings[j]) + 1;

			memcpy((char *)StringTable, (char *)NewStringTable, new_size);
			bin->shdr[bin->shdr[i].sh_link].sh_size = new_size; //update new strtab size
        		if (msync(newbin->mem, newbin->size, MS_SYNC) < 0) {
                		perror("msync");
                		return -1;
        		}
			break;
		}
		symtab = (Elf64_Sym *)&newbin->mem[newbin->shdr[i].sh_offset];
		for (j = 0; j < string_count; j++) {
			printf("%s\n", &StringTable[symtab->st_name]);
			symtab++;
		}
		unloadElf(bin);
		rename(TMP, path);
		bin = newbin;
	return 0;
}


/*
 * We just randomize the addresses of functions
 * NOTE: We do not create a new string table as we do with randomize_shdr's, although it may be more effective.
 */
int randomize_syms(ElfBin_t *bin)
{
	Elf64_Sym *symtab, *sp;
        char *SymStrTable;
        unsigned int i, j, symcount, index, fcount, c, assignedCount = 0;
	Elf64_Addr oldsymVals[MAX_SYM_COUNT];
	Elf64_Addr newsymVals[MAX_SYM_COUNT];
	int indexes[MAX_SYM_COUNT];

	ElfBin_t *target = bin;
	
        for (i = 0; i < target->ehdr->e_shnum; i++)
                if (target->shdr[i].sh_type == SHT_SYMTAB) {
                        SymStrTable = (char *)&target->mem[target->shdr[target->shdr[i].sh_link].sh_offset];
                        sp = symtab = (Elf64_Sym *)&target->mem[target->shdr[i].sh_offset];
			srand(time(0));
                        for (fcount = 0, j = 0; j < target->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) 
				if (ELF64_ST_TYPE(symtab->st_info) == STT_FUNC || ELF64_ST_TYPE(symtab->st_info) == STT_OBJECT) {
                        		oldsymVals[fcount] = symtab->st_value;
					fcount++;
				}
			for (j = 0; j < fcount;) { 
loop:
				index = rand() % fcount; 
				for (c = 0; c < assignedCount; c++) 
					if (indexes[c] == index)
						goto loop;
				newsymVals[assignedCount] = oldsymVals[index];
				indexes[assignedCount] = index;
				assignedCount++, j++;
			}	
			for (symtab = sp, c = 0, j = 0; j < target->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++)
				if (ELF64_ST_TYPE(symtab->st_info) == STT_FUNC || ELF64_ST_TYPE(symtab->st_info) == STT_OBJECT) {
					symtab->st_value = newsymVals[c++];
				}
				
                }
	if (msync(target->mem, target->size, MS_SYNC) < 0) {
		perror("msync");
		return -1;
	}
        return 0;
}

/*
 * Create a new string table for the shdrs that is randomly ordered
 * it also keeps the section types so that they match the section name type.
 * I.E wherever .text gets put, it will say SHT_PROGBITS.
 */
int randomize_shdrs(ElfBin_t *bin)
{
	Elf64_Ehdr *ehdr = bin->ehdr;
	Elf64_Shdr *shdr = bin->shdr;
	uint32_t i, j, count, stringCount, offset, strtblLen, index, assignedCount = 0;
	uint32_t strtab_size = shdr[ehdr->e_shstrndx].sh_size;
	char *StringTable = (char *)&bin->mem[shdr[ehdr->e_shstrndx].sh_offset];
	char **stblVector1 = (char **) malloc(sizeof(char *) * ehdr->e_shnum + 1);
	char **stblVector2 = (char **) malloc(sizeof(char *) * ehdr->e_shnum + 10);
	char **assignedStr = (char **) malloc(sizeof(char *) * ehdr->e_shnum + 1);
	char *StringTableNew, *p;
	uint8_t dynamicSet = 0;
	uint8_t symtabSet = 0;
	uint8_t strtabSet = 0;

	for (i = 0; i < ehdr->e_shnum; i++) 
		stblVector1[i] = strdup(&StringTable[shdr[i].sh_name]);	
	srand(time(0));
	stringCount = i - 1;
	for (i = 0; i < ehdr->e_shnum;) {
loop:
		index = rand() % ehdr->e_shnum;
		for (j = 0; j < assignedCount; j++)
			if (!strcmp(assignedStr[j], stblVector1[index])) 
				goto loop;
		stblVector2[i++] = strdup(stblVector1[index]);
		assignedStr[assignedCount++] = strdup(stblVector1[index]);
	}  
	for (strtblLen = 0, i = 0; i < ehdr->e_shnum; i++) 
		strtblLen += strlen(stblVector2[i]) + 1;
	StringTableNew = (char *)malloc(strtblLen);
	p = StringTableNew;
	*p = '\0';
	for (p = StringTableNew + 1, i = 0; i < ehdr->e_shnum; i++) {
                strcpy(p, stblVector2[i]); 
                p += strlen(p) + 1;
                *p = 0;
        }
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_NULL) 
			shdr[i].sh_name = 0;
		if (!strcmp(stblVector2[i], ".dynamic"))
			if(!dynamicSet)
				continue;
		if (!strcmp(stblVector2[i], ".symtab"))
			if (!symtabSet)
				continue;
		if (!strcmp(stblVector2[i], ".strtab"))
			if (!strtabSet)
				continue;
	
		if (!strcmp(&StringTable[shdr[i].sh_name], ".symtab")) {
			shdr[i].sh_name = get_strtbl_offset(StringTableNew, ".symtab", ehdr->e_shnum);
			symtabSet = 1;
			continue;
		}
		
		if (!strcmp(&StringTable[shdr[i].sh_name], ".strtab")) {
			shdr[i].sh_name = get_strtbl_offset(StringTableNew, ".strtab", ehdr->e_shnum);
			strtabSet = 1;
			continue;
		}

		if (!strcmp(&StringTable[shdr[i].sh_name], ".dynamic")) {
                        shdr[i].sh_name = get_strtbl_offset(StringTableNew, ".dynamic", ehdr->e_shnum);
			dynamicSet = 1;
			continue;
                }
		shdr[i].sh_name = get_strtbl_offset(StringTableNew, stblVector2[i], ehdr->e_shnum);
		for (count = 0; count < MAX_SHDR_TYPES; count++) {
               		if (!strcmp(stblVector2[i], section_type[count].name)) {
                        	shdr[i].sh_type = section_type[count].type;
				switch(shdr[i].sh_type) {
				case SHT_SYMTAB:
                                	shdr[i].sh_entsize = 0x18;
                                	break;
				case SHT_DYNSYM:
                                	shdr[i].sh_entsize = 0x18;
                                	break;
				case SHT_REL:
                                        shdr[i].sh_entsize = 0x08;
					break;
				}
			}
		}
	}
done:
	memcpy((uint8_t *)StringTable, (uint8_t *)StringTableNew, strtab_size);
	if (msync(bin->mem, bin->size, MS_SYNC) < 0) {
		perror("randomize_shdrs failed with msync()");
		exit(-1);
	}
		
	return 0;
}


int RelocateCode(ElfBin_t *obj, ElfBin_t *host)
{ 
        Elf64_Rela *rela;
        Elf64_Sym *symtab, *symbol;
        Elf64_Shdr *targetShdr;
	Elf64_Addr relVal;
        Elf64_Addr targetAddr;
	Elf64_Addr objVaddr;
        Elf64_Addr *relocPtr;

 	int TargetIndex;
        int i, j, secLen, symstrndx;
	
	uint8_t *RelocPtr;
	char *SymStringTable, *StringTable;

	objVaddr = host->textVaddr - PAGE_ALIGN_UP(obj->size); // + sizeof(Elf64_Ehdr);
	
	printf("[!] Maya's Mind-- injection address: 0x%lx\n", objVaddr);
        
	/*
	 * Adjust section header addresses in relocation
 	 * object to help us during the relocation process.
	 */
	for (secLen = 0, i = 0; i < obj->ehdr->e_shnum; i++) {
                if (obj->shdr[i].sh_type == SHT_PROGBITS) {
                        obj->shdr[i].sh_addr = objVaddr + obj->shdr[i].sh_offset; //secLen;
                        secLen += obj->shdr[i].sh_size;
                }
                if (obj->shdr[i].sh_type == SHT_STRTAB && i != obj->ehdr->e_shstrndx)
                        symstrndx = i;
        }

	SymStringTable = (char *)&obj->mem[obj->shdr[symstrndx].sh_offset];
	StringTable = (char *)&obj->mem[obj->shdr[obj->ehdr->e_shstrndx].sh_offset];
	
	for (i = 0; i < obj->ehdr->e_shnum; i++) {
		switch(obj->shdr[i].sh_type) {
			case SHT_RELA:
#ifdef DEBUG
				printf("[!] Process relocations from section: %s\n", (char *)&StringTable[obj->shdr[i].sh_name]);
#endif
				rela = (Elf64_Rela *)&obj->mem[obj->shdr[i].sh_offset];
				for (j = 0; j < obj->shdr[i].sh_size/sizeof(Elf64_Rela); j++, rela++) {
					/* 	
					 * Get Symbol table
					 */
					symtab = (Elf64_Sym *)&obj->mem[obj->shdr[obj->shdr[i].sh_link].sh_offset];
		                       
				       /* 
					* symbol we are applying relocation to 
					*/
                                	symbol = (Elf64_Sym *)&symtab[ELF64_R_SYM(rela->r_info)];
					if (symbol->st_shndx > 12) //bug workaround
						continue;
						
					/*
					 * Section to modify 
					 */
					targetShdr = (Elf64_Shdr *)&obj->shdr[obj->shdr[i].sh_info];
					
					/*
					 * Relocation unit address
					 */
					targetAddr = targetShdr->sh_addr + rela->r_offset;
						
					/*
					 * Relocation pointer to reloc unit
					 */
					relocPtr = (Elf64_Addr *)&obj->mem[obj->shdr[obj->shdr[i].sh_info].sh_offset + rela->r_offset];
					
					/*
					 * First computation Value to assign relocation unit (S: Symbol Value)
					 */
					relVal = symbol->st_value;          
					relVal += obj->shdr[symbol->st_shndx].sh_addr;
					
					/*
					 * Apply relocation and complete the computation
					 */
					int64_t realOffset;
					int32_t truncOffset;
					switch(ELF64_R_TYPE(rela->r_info)) {
						case R_X86_64_PC32:
							/* S + A - P */
							realOffset = relVal + rela->r_addend - targetAddr;
                                                        truncOffset = (realOffset & 0xffffffff);
							if (realOffset < INT32_MIN || realOffset > INT32_MAX) 
								break;
							*(uint32_t *)relocPtr = truncOffset;
#ifdef DEBUG
							printf("R_X86_64_PC32: Relocation unit address/value pair for %s: 0x%lx/%x (addend: %x)\n", 
							(char *)&SymStringTable[symbol->st_name], targetAddr, (uint32_t)*(uint32_t *)relocPtr, rela->r_addend);
#endif
							break;
						case R_X86_64_32:
							/* S + A */
							relVal += rela->r_addend;
							if (relVal <= UINT32_MAX) {
								uint32_t truncatedVal = (relVal & 0xffffffff);
								*(uint32_t *)relocPtr = truncatedVal;
#ifdef DEBUG
								printf("R_X86_64_32: Relocation unit address/value pair for %s: 0x%lx/%x (addend: %x)\n", 
                                                                (char *)&SymStringTable[symbol->st_name], targetAddr, (uint32_t)*(uint32_t *)relocPtr, rela->r_addend);
#endif
							}

							break;
						case R_X86_64_32S:
							/* S + A and SIGNEXTEND */
							relVal += rela->r_addend;
							if (((int64_t)relVal <= INT32_MAX && (int64_t)relVal >= INT32_MIN)) {
								uint32_t truncatedVal = (relVal & 0xffffffff);
								*(uint32_t *)relocPtr = truncatedVal;
#ifdef DEBUG
				 		       		printf("R_X86_64_PC32S: Relocation unit address/value pair for %s: 0x%lx/%x (addend: %x)\n", 
 	                                                	(char *)&SymStringTable[symbol->st_name], targetAddr, (uint32_t)*(uint32_t *)relocPtr, rela->r_addend);
#endif
							}
							break;
						case R_X86_64_64:
							/* S + A */
							relVal += rela->r_addend;
							*(uint64_t *)relocPtr = relVal;
							
#ifdef DEBUG
							printf("R_X86_64_64: Relocation unit address/value pair for %s: 0x%lx/%lx (addend: %x)\n",
							(char *)&SymStringTable[symbol->st_name], targetAddr, (uint64_t)*(uint64_t *)relocPtr, rela->r_addend);
#endif
							break;
						default:
							printf("Unknown relocation type: %lx\n", rela->r_info);
					}
				}
			}
		}

	return 0;
}
	
int loadElf_rdonly(const char *path, ElfBin_t *bin, int prot, int flags)
{
        int fd, i, interp = 0;
        struct stat st;
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        uint8_t *mem = bin->mem;

        if ((fd = open(path, O_RDONLY)) < 0) {
                perror("open");
                return -1;

        }

        if (fstat(fd, &st) < 0) {
                perror("fstat");
                return -1;
        }

        bin->st = st;
        bin->mem = mem = mmap(NULL, PAGE_ALIGN_UP(st.st_size), prot, flags, fd, 0);
        if (bin->mem == MAP_FAILED) {
                perror("mmap");
                return -1;
        }

        bin->mmap_flags = flags;
        bin->mmap_prot = prot;
        bin->path = strdup(path);
        bin->size = st.st_size;
        bin->ehdr = ehdr = (Elf64_Ehdr *)mem;
        bin->phdr = phdr = (Elf64_Phdr *)(mem + ehdr->e_phoff);
        bin->shdr = shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);
        bin->type = ehdr->e_type;
        bin->origEntry = ehdr->e_entry;

        bin->StringTable = (char *)&bin->mem[shdr[ehdr->e_shstrndx].sh_offset];

        if (ehdr->e_type == ET_EXEC) {
                for (i = 0; i < ehdr->e_phnum; i++) {
                        if (phdr[i].p_type == PT_INTERP)
                                bin->interpSize = phdr[i].p_filesz;
                        if ((phdr[i].p_flags & PF_X) && phdr[i].p_type == PT_LOAD) {
                                /* Get PT_LOAD vaddr's */
                                bin->textOff = phdr[i].p_offset;
                                bin->textVaddr = phdr[i].p_vaddr;
                                bin->textSize = phdr[i].p_filesz;
                                bin->origTextSize = phdr[i].p_filesz;
                                bin->dataOff = phdr[i + 1].p_offset;
                                bin->dataSize = phdr[i + 1].p_filesz;
                                bin->dataVaddr = phdr[i + 1].p_vaddr;
                        }
                        if (phdr[i].p_type == PT_INTERP)
				    interp++;

                }
                if (!interp && strcmp(bin->path, "./stub")) {
                        printf("[!] executable: '%s' appears to be statically linked. Maya does not yet support statically linked programs.\n", path);
                        exit(0);
                }
        }
        close(fd);

}

int phdr_is_valid(ElfBin_t *bin, int type)
{
	Elf64_Phdr *phdr = bin->phdr;
	int i;
	
	for (i = 0; i < bin->ehdr->e_phnum; i++) {
		if (phdr[i].p_type == type)
			return 1;
	}
	return 0;
}


int loadElf(const char *path, ElfBin_t *bin, int prot, int flags)
{
	int fd, i, interp = 0, stub = 0;
	struct stat st;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem = bin->mem;

	if ((fd = open(path, O_RDWR)) < 0) {
		perror("open");	
		return -1;
	
	}
	
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return -1;
	}
	
	bin->st = st;
	bin->mem = mem = mmap(NULL, PAGE_ALIGN_UP(st.st_size), prot, flags, fd, 0);
	if (bin->mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	
	bin->mmap_flags = flags;
	bin->mmap_prot = prot;
	bin->path = strdup(path);
	bin->size = st.st_size;
	bin->ehdr = ehdr = (Elf64_Ehdr *)mem;
	bin->phdr = phdr = (Elf64_Phdr *)(mem + ehdr->e_phoff);
	bin->shdr = shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);
	bin->type = ehdr->e_type;
	bin->origEntry = ehdr->e_entry;
	
	bin->StringTable = (char *)&bin->mem[shdr[ehdr->e_shstrndx].sh_offset];

	/*
	 * We only care about these for ./tracer
	 */
	if (strcmp(path, "./tracer.o") == 0) {
		bin->dataOff = 0;
		for (i = 0; i < bin->ehdr->e_shnum; i++) {
			if (!strcmp((char *)&bin->StringTable[bin->shdr[i].sh_name], ".data")) {
				bin->dataOff = bin->shdr[i].sh_offset;	
				break;
			}
		}
		/* Get remote symbol addrs */
		bin->entryPoint = GetSymAddr("_start", bin);	
		bin->brainsymbol.hostEntry = GetSymAddr("knowledge", bin) + KNOWLEDGE_HOST_ENTRY_OFFSET + bin->dataOff;
		bin->brainsymbol.mayaModes = GetSymAddr("maya_modes", bin) + bin->dataOff;
		bin->brainsymbol.mayaCflow = GetSymAddr("maya_cflow", bin) + bin->dataOff;
		bin->brainsymbol.functionSizes = GetSymAddr("functionSizes", bin) + bin->dataOff;
		bin->brainsymbol.fingerprint = GetSymAddr("fingerprint", bin) + sizeof(Elf64_Ehdr);
		bin->brainsymbol.verify_fingerprint = GetSymAddr("verify_fingerprint", bin) + sizeof(Elf64_Ehdr);
		bin->brainsymbol.trace_thread = GetSymAddr("trace_thread", bin) + sizeof(Elf64_Ehdr);
		
		/* Get remote symbol sizes */	
		bin->brainsymbol.sizes.mayaModes = GetSymSize("maya_modes", bin);
		bin->brainsymbol.sizes.mayaCflow = GetSymSize("maya_cflow", bin);
		bin->brainsymbol.sizes.functionSizes = GetSymSize("functionSizes", bin);
		bin->brainsymbol.sizes.fingerprint = GetSymSize("fingerprint", bin);
		bin->brainsymbol.sizes.verify_fingerprint = GetSymSize("verify_fingerprint", bin);
		bin->brainsymbol.sizes.trace_thread = GetSymSize("trace_thread", bin); 
	
		if (opts.verbose) {
			printf("\n[+] Brain Attribute Locations\n");
			printf("- _start: %lx\n", bin->entryPoint);
			printf("- hostEntry: %lx\n", bin->brainsymbol.hostEntry);
			printf("- mayaModes: %lx\n", bin->brainsymbol.mayaModes);
			printf("- mayaCflow: %lx\n", bin->brainsymbol.mayaCflow);
			printf("- fingerprint: %lx\n", bin->brainsymbol.fingerprint);
			printf("- verify_fingerprint: %lx\n", bin->brainsymbol.verify_fingerprint);
			printf("- trace_thread: %lx\n", bin->brainsymbol.trace_thread);
		}
	}

	if (ehdr->e_type == ET_EXEC) {
		for (i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_INTERP)
				bin->interpSize = phdr[i].p_filesz;
			if ((phdr[i].p_flags & PF_X) && phdr[i].p_type == PT_LOAD) { 
				
				/*
				 * For the host executable:
				 * We must make the text segment writable because the
				 * brain 'tracer.o' has both its text and data sections
				 * in the text of the host executable (Data must be +W).
				 */
				if ((flags & MAP_SHARED) && strstr(path, ".maya")) {
					phdr[i].p_flags |= PF_W; // text +write 
					phdr[i].p_align = 0x1000; // disable large pages for paxctl compatibility (We infect with page boundaries)
					phdr[i + 1].p_align = 0x1000;
				}

				/* Get PT_LOAD vaddr's */
				bin->textOff = phdr[i].p_offset;
				bin->textVaddr = phdr[i].p_vaddr;
				bin->textSize = phdr[i].p_filesz;
				bin->origTextSize = phdr[i].p_filesz;
				bin->dataOff = phdr[i + 1].p_offset;
				bin->dataSize = phdr[i + 1].p_filesz;
				bin->dataVaddr = phdr[i + 1].p_vaddr;
				
				if (strcmp(bin->path, "./stub")) {
					if (ehdr->e_shnum != 0 && ehdr->e_shstrndx) {
						printf("[+] Extracting information for RO Relocations\n");
						ro_relocs.loadbase = bin->dataVaddr & ~(PAGE_SIZE - 1);
						ro_relocs.got_offset = get_offset_of_section(bin, ".got.plt");
						ro_relocs.got_offset = ro_relocs.got_offset - bin->dataOff;
						ro_relocs.got_size = get_size_of_section(bin, ".got.plt");
					} else {
						//printf("[!] executables: '%s' has no section header table which is required for read-only relocations feature\n", path);
						maya_mode.ro_relocs = 0;
					}
				
					if (interp == 0) {
						printf("[!] executable: '%s' is static, and therefore read-only relocations do not apply\n", path);
						maya_mode.ro_relocs = 0;
					}
				} 
				
			} 	

			if (phdr[i].p_type == PT_INTERP)
				interp++;
					
		}
		if (!interp && strcmp(bin->path, "./stub")) {
			printf("[!] executable: '%s' appears to be statically linked. Maya does not yet support statically linked programs.\n", path);
			exit(0);
		}
	}
	close(fd);
	
}


	
/*
 * ./tracer.o must be fixed up manually with certain
 * values that aren't known until it is injected into the
 * host executable.
 */
void imbue_knowledge(ElfBin_t *rel, ElfBin_t *exe)
{
	int i;
	uint8_t *p;
	unsigned int knowledgeOffset, cryptinfo_Offset, fpOffset, ciOffset, cfOffset, nmOffset, rrOffset;
	unsigned int knowledgeSize;
	/*
	 * imbue functionSizes
	 */
	
	p = (uint8_t *)&rel->mem[rel->brainsymbol.functionSizes + FSIZES_TRACE_THREAD_OFFSET];
	*(unsigned int *)p = rel->brainsymbol.sizes.trace_thread;
	
	p = (uint8_t *)&rel->mem[rel->brainsymbol.functionSizes + FSIZES_VALIDATE_FINGERPRINT_OFFSET];
	*(unsigned int *)p = rel->brainsymbol.sizes.verify_fingerprint;
	
	p = (uint8_t *)&rel->mem[rel->brainsymbol.functionSizes + FSIZES_FINGERPRINT_OFFSET];
	*(unsigned int *)p = rel->brainsymbol.sizes.fingerprint;
	
	/*
 	 * imbue knowledge.hostEntry
	 */
	p = (uint8_t *)&rel->mem[rel->brainsymbol.hostEntry];
	*(unsigned long *)p = exe->origEntry;
	
	/*
	 * imbue maya_modes_t struct
	 */
	p = (uint8_t *)&rel->mem[rel->brainsymbol.mayaModes];
	memcpy((maya_modes_t *)p, (maya_modes_t *)&maya_mode, sizeof(maya_modes_t));
	
	/*
	 * imbue knowledge.maya_cflow (maya_cflow_t)
	 */
	p = (uint8_t *)&rel->mem[rel->brainsymbol.mayaCflow];
	memcpy((maya_cflow_t *)p, (maya_cflow_t *)maya_cflow, sizeof(maya_cflow_t) * MAX_CFLOW_ITEMS);

        /*
         * Imbue crypt_item_count
         */
	
	knowledgeOffset = rel->brainsymbol.hostEntry;
	
	if (opts.layers != MAYA_L0_PROT) {
		ciOffset = knowledgeOffset + KNOWLEDGE_CRYPT_ITEM_COUNT_OFFSET;
       		p = (uint8_t *)&rel->mem[ciOffset];
     		memcpy((void *)p, (void *)&exe->crypt_item_count, sizeof(unsigned int));
	}
	
	/*
	 * Imbue knowledge.cflow (Control flow integrity data records)
	 */
	if (opts.cflow) {
   		cfOffset = knowledgeOffset + KNOWLEDGE_CFLOW_ITEM_COUNT_OFFSET;
      		p = (uint8_t *)&rel->mem[cfOffset];
      		memcpy((void *)p, (void *)&exe->cflow_count, sizeof(unsigned int));
	}
	
	/*
	 * Imbue knowledge.nanomite (Nanomite data records)
	 */
	if (opts.nanomites) {
		nmOffset = knowledgeOffset + KNOWLEDGE_NANOMITE_OFFSET;
		p = (uint8_t *)&rel->mem[nmOffset];
		memcpy((void *)p, (void *)exe->nanomites, sizeof(nanomite_t) * MAX_NANOMITES);
	}

	if (opts.layers == MAYA_L2_PROT) {
		/*
	 	* Now we imbue the salsa encryption data for the different sections
	 	* we want to apply it on, into the knowledge.cryptinfo_<section> areas
	 	*/

	
		cryptinfo_text.hostCodeOffset = text.section_offset + PAGE_ALIGN_UP(rel->size + JMPCODE_LEN);
		cryptinfo_text.hostCodeVaddr = text.section_vaddr; 
		cryptinfo_text.origTextSize = text.section_size;
		knowledgeOffset = rel->brainsymbol.hostEntry; //GetSymAddr("knowledge", rel);
        	cryptinfo_Offset = knowledgeOffset + KNOWLEDGE_CRYPTINFO_TEXT_OFFSET;
	       
	       /*
	 	* Imbue knowledge.cryptinfo_text
	 	*/
		p = (uint8_t *)&rel->mem[cryptinfo_Offset];
		memcpy((void *)p, (void *)&cryptinfo_text, sizeof(cryptInfo_t));
	
	       /*
	 	* Imbue knowledge.cryptinfo_data
	 	*/
		cryptinfo_data.hostCodeOffset = data.section_offset + PAGE_ALIGN_UP(rel->size + JMPCODE_LEN);
		cryptinfo_data.hostCodeVaddr = data.section_vaddr;
		cryptinfo_data.origDataSize = data.section_size;
	
		cryptinfo_Offset = knowledgeOffset + KNOWLEDGE_CRYPTINFO_DATA_OFFSET;
	
 		p = (uint8_t *)&rel->mem[cryptinfo_Offset];
       		memcpy((void *)p, (void *)&cryptinfo_data, sizeof(cryptInfo_t));

	
		/*
	 	 * Imbue knowledge.cryptinfo_rodata
	 	 */
		cryptinfo_rodata.hostCodeOffset = rodata.section_offset + PAGE_ALIGN_UP(rel->size + JMPCODE_LEN);
        	cryptinfo_rodata.hostCodeVaddr = rodata.section_vaddr;
        	cryptinfo_rodata.origDataSize = rodata.section_size;

        	cryptinfo_Offset = knowledgeOffset + KNOWLEDGE_CRYPTINFO_RODATA_OFFSET;

        	p = (uint8_t *)&rel->mem[cryptinfo_Offset];
        	memcpy((void *)p, (void *)&cryptinfo_rodata, sizeof(cryptInfo_t));

	       /*
	 	* Imbue knowledge.cryptinfo_plt
	 	*/
		cryptinfo_plt.hostCodeOffset = plt.section_offset + PAGE_ALIGN_UP(rel->size + JMPCODE_LEN);
     		cryptinfo_plt.hostCodeVaddr = plt.section_vaddr;
        	cryptinfo_plt.origDataSize = plt.section_size;

        	cryptinfo_Offset = knowledgeOffset + KNOWLEDGE_CRYPTINFO_PLT_OFFSET;

        	p = (uint8_t *)&rel->mem[cryptinfo_Offset];
        	memcpy((void *)p, (void *)&cryptinfo_plt, sizeof(cryptInfo_t));
		
		/*
		 * Imbue knowledge.fingerprint
		 */
		fpOffset = knowledgeOffset + KNOWLEDGE_FINGERPRINT_OFFSET;
		
		p = (uint8_t *)&rel->mem[fpOffset];
		memcpy((void *)p, (void *)fingerprint, FINGERPRINT_SIZE);
		
		/*
		 * Imbue knowledge.ro_reloc_info	
	   	 */
		
		rrOffset = knowledgeOffset + KNOWLEDGE_RO_RELOCS_OFFSET;
		p = (uint8_t *)&rel->mem[rrOffset];
		memcpy((void *)p, (void *)&ro_relocs, sizeof(ro_relocs_t));
	
		/*
		 * This is good! We no longer have to depend on #define KNOWLEDGE_SIZE
		 * we get it dynamically from tracer.o symbol table
		 */
		if ((knowledgeSize = GetSymSize("knowledge", rel)) == 0) {
			printf("[!] Failed at retrieving the knowledge symbol from %s\n", rel->path);
			exit(0);
		}
		
		printf("[+] Encrypting knowledge: %d bytes\n", knowledgeSize);

		/* Transform knowledge */
		p = (uint8_t *)&rel->mem[knowledgeOffset + KNOWLEDGE_HOST_ENTRY_OFFSET];
		for (i = 0; i < knowledgeSize; i++)
			rel->mem[knowledgeOffset + KNOWLEDGE_HOST_ENTRY_OFFSET + i] ^= ((0xA * i) & 0xff);
		
		/* Transform trace_thread() */
		
		p = (uint8_t *)&rel->mem[rel->brainsymbol.trace_thread];
		for (i = 0; i < rel->brainsymbol.sizes.trace_thread; i++) {
			rel->mem[rel->brainsymbol.trace_thread + i] ^= ((0xA * i) & 0xff);
		} 

		/* Encode/Obfuscate fingerprint functions */
		p = (uint8_t *)&rel->mem[rel->brainsymbol.fingerprint];
		for (i = 0; i < rel->brainsymbol.sizes.fingerprint; i++)
			rel->mem[rel->brainsymbol.fingerprint + i] ^= ((0xA * i) & 0xff);

		p = (uint8_t *)&rel->mem[rel->brainsymbol.verify_fingerprint];
		for (i = 0; i < rel->brainsymbol.sizes.verify_fingerprint; i++)
			rel->mem[rel->brainsymbol.verify_fingerprint + i] ^= ((0xA * i) & 0xff);

	}
	
}	

	
/*
 * The following code is responsible our voodoo decryption
 * engine into the target(encrypted) executable. This is actually
 * the reverse process of how most packers/protectors work which
 * essentially inject the encrypted executable into the stub/decryptor engine.
 * This technique we are doing here gives us more fine control over what
 * and how we want things protected. The end result looks like this:
 * 
 * Original exec: [ehdr][phdrs][text][data]
 * After injection: [ehdr][voodo.o][phdrs][text][data]
 */
unsigned int paddingSize;

int injectObject(ElfBin_t *rel, ElfBin_t *exe)
{
	Elf64_Ehdr *ehdr = exe->ehdr;
	Elf64_Phdr *phdr = exe->phdr;
	Elf64_Shdr *shdr = exe->shdr;
	uint8_t *mem = exe->mem;
	char *StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];

	int text_found = 0, i;
        Elf64_Addr orig_entry_point = ehdr->e_entry; 
 	Elf64_Addr origText;

	paddingSize = PAGE_ALIGN_UP(rel->size + JMPCODE_LEN);
	
	if (opts.verbose)
		printf("[+] Padding Size needed: %x\n", paddingSize);

        phdr = (Elf64_Phdr *)(exe->mem + ehdr->e_phoff);

	phdr[0].p_offset += paddingSize;
	phdr[1].p_offset += paddingSize;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (text_found)
			phdr[i].p_offset += paddingSize;
	
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R|PF_X)) {
				origText = phdr[i].p_vaddr;
				phdr[i].p_vaddr -= paddingSize;
				phdr[i].p_paddr -= paddingSize;
				phdr[i].p_filesz += paddingSize;
				phdr[i].p_memsz += paddingSize;
				text_found = 1;
		}
	}
	if (!text_found) {
		printf("Error, unable to locate text segment in target executable: %s\n", exe->path);
		return -1;
	}
	
	
	ehdr->e_entry = origText - paddingSize + sizeof(Elf64_Ehdr);
	
	shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];
	for (i = 0; i < ehdr->e_shnum; i++) { 
		
#ifdef DEBUG
		if (!strcmp((char *)&StringTable[shdr[i].sh_name], ".text")) {
			shdr[i].sh_offset = sizeof(Elf64_Ehdr); // -= (uint32_t)paddingSize;
			shdr[i].sh_addr = origText - paddingSize + sizeof(Elf64_Ehdr);
			shdr[i].sh_size += rel->size;
		}  
		else 
#endif
			shdr[i].sh_offset += paddingSize;
	}
 	       
        ehdr->e_shoff += paddingSize;
        ehdr->e_phoff += paddingSize;
	
	imbue_knowledge(rel, exe);
	
	/*
	 * Zero out section and symbol string tables from tracer.o before
	 * we inject it into host executable.
	 */
	zero_string_tables(rel);
	/*
 	* TODO 
 	* Make inject_tracer_code return the name of newbin.maya
 	* and then we will run randomize_shdrs()
 	*/
	inject_tracer_code(rel->size, exe, rel, orig_entry_point);
	
	return 0;
}
	
/*
 * The following function leaves an executable looking like so:
 * [elf file header][tracer.o][text segment][data segment]
 */
void inject_tracer_code(unsigned int psize, ElfBin_t *exe, ElfBin_t *rel, Elf64_Addr entry_point)
{
        
        int ofd;
        unsigned int c;
        int i, t = 0, ehdr_size = sizeof(Elf64_Ehdr);
	unsigned char *mem = exe->mem;
	unsigned char *parasite = rel->mem + ehdr_size;
	char *host = exe->path, *protected; 
	ElfBin_t newBin;
	struct stat st;

	memcpy((struct stat *)&st, (struct stat *)&exe->st, sizeof(struct stat));

        /* eot is: 
         * end_of_text = e_hdr->e_phoff + nc * e_hdr->e_phentsize;
         * end_of_text += p_hdr->p_filesz;
         */ 
        extern int return_entry_start;

        if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1) {
                perror("tmp binary: open");
                exit(-1);
        }
  	
	/*
 	 * Write first 64 bytes of original binary (The elf file header) 
	 * [ehdr] 
	 */
        if ((c = write(ofd, mem, ehdr_size)) != ehdr_size) {
                printf("failed writing ehdr of tracer.o: %s\n", strerror(errno));
                exit(-1);
        }
        
	/*
 	 * Now inject the decryption engine (tracer.o) 
	 * [ehdr][tracer.o]
	 */
        if ((c = write(ofd, parasite, rel->size - ehdr_size)) != rel->size - ehdr_size) {
                printf("injecting tracer.o failed (sys_write): %s\n", strerror(errno));
                exit(-1);
        }

	/*
	 * Seek to end of tracer.o + PAGE boundary  
	 * [ehdr][tracer.o][pad]
	 */
	uint32_t offset = sizeof(Elf64_Ehdr) + paddingSize;
        if ((c = lseek(ofd, offset, SEEK_SET)) != offset) {
                printf("lseek only wrote %d bytes: %s\n", c, strerror(errno));
                exit(-1);
        }
	
	/*
	 * Write the rest of the original binary
	 * [ehdr][tracer.o][pad][phdrs][text][data][shdrs]
	 */
        mem += sizeof(Elf64_Ehdr);
        
	unsigned int final_length = st.st_size - (sizeof(Elf64_Ehdr)); // + exe->ehdr->e_shnum * sizeof(Elf64_Shdr));
        if ((c = write(ofd, mem, final_length)) != final_length) {
                printf("Failed writing binary, wrote %d bytes: %s\n", c, strerror(errno));
                exit(-1);
        }
        
        rename(TMP, protected = (char *)(uintptr_t)xfmtstrdup("%s.maya", host));
        
	if (loadElf(protected, &newBin, PROT_READ|PROT_WRITE, MAP_SHARED) < 0) {
		printf("[!] Unable to load %s: %s\n", protected, strerror(errno));
		exit(-1);
	}
	
	/*
	 * These are ways to obfuscate the string table for sections and symbols
	 * if we decide to keep them, but discarding them is probably most secure.
	 */
	
	if (opts.obfuscate) {
	//	inject_new_symbol_strings(&newBin);
		randomize_syms(&newBin);
		randomize_shdrs(&newBin);
	}

	
	if (opts.strip) {
		zero_string_tables(&newBin);
		newBin.ehdr->e_shnum = 0;
		newBin.ehdr->e_shoff = 0;
		newBin.ehdr->e_shstrndx = 0;
	}
	
	unloadElf(&newBin);
	
	
	close(ofd);

	
}
 
#define ELF_VERSION_OFFSET 8 // EI_VERSION in ELF header

int add_layer_3(ElfBin_t *target, ElfBin_t *stub)
{
	int fd, i;
	unsigned int injectionAddr, injectionOff, metaDataOff, metaDataVaddr, bss_size;
	stub_meta_t stub_data;
	size_t b;
	uint8_t *mapping;

	char *name = (char *)(uintptr_t)xfmtstrdup("%s.final", target->path);
	
	if ((fd = open(name, O_CREAT|O_RDWR, target->st.st_mode)) < 0) {
		printf("[!] Unable to create output file %s: open() failure: %s\n", name, strerror(errno));
		return -1;
	}
	
	for (i = 0; i < stub->ehdr->e_phnum; i++)
		if (stub->phdr[i].p_offset != 0 && stub->phdr[i].p_type == PT_LOAD) {
			/*
			 * Find end of data segment (Injection point)
			 */
			bss_size = stub->phdr[i].p_memsz - stub->phdr[i].p_filesz;
			metaDataVaddr = stub->phdr[i].p_vaddr + stub->phdr[i].p_memsz;
			metaDataOff = stub->phdr[i].p_offset + stub->phdr[i].p_memsz;
			injectionOff = stub->phdr[i].p_offset + stub->phdr[i].p_memsz + sizeof(stub_meta_t);
			injectionAddr = stub->phdr[i].p_vaddr + stub->phdr[i].p_memsz + sizeof(stub_meta_t);
			/*
			 * Modify phdr's to reflect extended data segment size
			 */
			stub->phdr[i].p_filesz += target->size + sizeof(stub_meta_t) + 4096;
			stub->phdr[i].p_memsz += target->size + sizeof(stub_meta_t) + 4096;
			stub->phdr[i].p_align = 0x1000;
			stub->phdr[i - 1].p_align = 0x1000;
			break;
		}
		
	size_t length = PAGE_ALIGN_UP(target->st.st_size + stub->size + 4095);

	/*
	 * Set stub meta data
	 */
	stub_data.len = target->size; // target->size;
	stub_data.location = injectionAddr;
	
	/*
	 * Remove section headers from stub
	 */
	
	stub->ehdr->e_shoff = 0;
	stub->ehdr->e_shnum = 0;
	stub->ehdr->e_shstrndx = 0; 
	
	stub->ehdr->e_flags = metaDataVaddr ^ META_XOR_BITS;

	/*
	 * Write out stub 
	 * [STUB]
	 */
	write(fd, stub->mem, metaDataOff);
	write(fd, (char *)&stub_data, sizeof(stub_meta_t));
	
	for (i = 0; i < target->size; i++)
		target->mem[i] ^= ((0xD * i) & 0xFF);

	write(fd, (char *)target->mem, PAGE_ALIGN_UP(target->size));
	fsync(fd);
	close(fd);

	close(fd);
	rename(name, target->path);
	printf("[+] Produced final layer 3 output file: %s\n", target->path);

	return 0;
	

}



