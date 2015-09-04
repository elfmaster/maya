#include "maya.h"

#define AUXV_COUNT 7

#define META_XOR_BITS 0xf3c9d12

#define HUGE_STACK_SIZE 4096 * 256

#define LINKER_SIZE 300000
#define LINKER_ADDR 0xD0000000

#define STUB_BASE 0xA00000 
#define STUB_META_LOCATION STUB_BASE + 8

#define PAGE_SIZE 4096
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE) 

#define HUGE_PAGE_SIZE 0x200000

#define SET_STACK_AND_JMP(stack, addr)__asm__ __volatile__("mov %0, %%rsp\n" \
                                            "push %1\n" \
                                            "mov $0, %%rax\n" \
                                            "mov $0, %%rbx\n" \
                                            "mov $0, %%rcx\n" \
                                            "mov $0, %%rdx\n" \
                                            "mov $0, %%rsi\n" \
                                            "mov $0, %%rdi\n" \
                                            "mov $0, %%rbp\n" \
                                            "ret" :: "r" (stack), "g" (addr))

        /* Linker specific ELF and mmap's */
         struct linker {
		Elf64_Addr entry;
                Elf64_Addr textVaddr;
                unsigned int textSize;
                unsigned int textOff;
                Elf64_Addr dataVaddr;
                unsigned int dataSize;
                unsigned int dataOff;
                unsigned char *text;
                unsigned char *data;
                Elf64_Ehdr *ehdr;
                Elf64_Phdr *phdr;
        } linker; // __attribute__((section(".data"))) = {0x00};

/*
 * Command line args and envp for building stack
 */
typedef struct {
	int size;
	int count;
	uint8_t *vector;
} auxv_t;

struct argdata {
	int argcount;
	int arglen;
	char *argstr;
	
	int envpcount;
	int envplen;
	char *envstr;
	auxv_t *saved_auxv;
}; 

#define JMP_ADDR(x) asm("\tjmp  *%0\n" :: "r" (x))
#define SET_STACK(x) asm("\tmovq %0, %%rsp\n" :: "r"(x))
#define ALLOCATE(size)  \
      _mmap2(0, (size), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)

void __stack_chk_fail(void);

void __stack_chk_fail(void) { }

void *_mmap2(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
        long mmap_fd = fd;
        unsigned long mmap_off = off;
        unsigned long mmap_flags = flags;
        void *ret;

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


void save_stack_data(int argc, char **argv, char **envp, struct argdata *args)
{
	unsigned char *mem, *mp;
        int size, i, j, tmp;
	char **envpp = envp;
	char *s;

	for (i = 0, size = 0, tmp = argc; tmp > 0; tmp--, i++)
		size += _strlen(argv[i]) + 1;

	args->argcount = argc;
	args->arglen = size;

	for (i = 0, size = 0; *envpp != NULL; envpp++, i++)   
		size += _strlen(*envpp);
	size += _strlen("LD_BIND_NOW=1");
	i++;
	size += i; // null bytes
	
	args->envpcount = i;
	args->envplen = size;

        args->argstr = (char *)(uintptr_t)ALLOCATE(args->arglen);
	args->envstr = (char *)(uintptr_t)ALLOCATE(args->envplen);
	
	/*
	 * Create one string of all args
	 */
        for (s = args->argstr, j = 0, i = 0; i < argc; i++) {
                while(j < _strlen(argv[i]))
                        s[j] = argv[i][j++];
                s[j] = '\0';
		s += _strlen(argv[i]) + 1;
                j = 0;
        }
	
	/*
	 * Create one string of all envp strings
	 */
	for (i = 0; *envp != NULL; envp++) {
		_strcpy(&args->envstr[i], *envp);
		i += _strlen(*envp) + 1;
	}
	_strcpy(&args->envstr[i], "LD_BIND_NOW=1");

}

unsigned long * create_stack(void)
{
        uint8_t *mem;
        mem = (void *)(uintptr_t)_mmap2(0, HUGE_STACK_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_GROWSDOWN|MAP_ANONYMOUS, -1, 0);
        if(mem == MAP_FAILED) {
                //_printf("[STUB] Internal stack allocation failed\n");
                Exit(-1);
        }
        return (unsigned long *)(mem + HUGE_STACK_SIZE);
}

/*
 * I must admit, my implementation in this function
 * is a bit confusing. I did not perhaps use the
 * most readable method of constructing the stack
 * (lots of pointer stuff)
 */
Elf64_Addr build_auxv_stack(ElfBin_t *elf, struct argdata *args)
{
	uint64_t *esp, *envp, *argv, esp_start;
	int i, count, totalsize, stroffset, len, argc;
	char *strdata, *s;
	void *stack;
	Elf64_auxv_t *auxv;

	count += sizeof(int); // argc
	count += args->argcount * sizeof(char *);
	count += sizeof(void *); // NULL
	count += args->envpcount * sizeof(char *);
	count += sizeof(void *); // NULL
	count += AUXV_COUNT * sizeof(Elf64_auxv_t);
	
	count = (count + 16) & ~(16 - 1);
	totalsize = count + args->envplen + args->arglen;
	totalsize = (totalsize + 16) & ~(16 - 1);
	
	stack = (void *)create_stack();
	
	esp = (uint64_t *)stack;
	uint64_t *sp = esp = esp - (totalsize / sizeof(void *));
	esp_start = (uint64_t)esp;
	strdata = (char *)(esp_start + count);  
	
	s = args->argstr;
	argv = esp;
	envp = argv + args->argcount + 1;
	
	*esp++ = args->argcount;
	for (argc = args->argcount; argc > 0; argc--) {
		_strcpy(strdata, s);
		len = _strlen(s) + 1;
		s += len;
		*esp++ = (uintptr_t)strdata;
		strdata += len;
	}
	
	*esp++ = (uintptr_t)0;
	
	for (s = args->envstr, i = 0; i < args->envpcount; i++) {
		_strcpy(strdata, s);
		len = _strlen(s) + 1;
		s += len;
		*esp++ = (uintptr_t)strdata;
		strdata += len;
	}
	
	*esp++ = (uintptr_t)0;
		
	/*
	 * Fill out auxillary vector portion of stack
	 * so we now have:
 	 * [argc][argv][envp][auxillary vector][argv/envp strings]
	 */
	_memcpy((void *)esp, (void *)args->saved_auxv->vector, args->saved_auxv->size);
	auxv = (Elf64_auxv_t *)esp;
	for (i = 0; auxv->a_type != AT_NULL; auxv++)
	{
		switch(auxv->a_type) {
			case AT_PAGESZ:
				auxv->a_un.a_val = PAGE_SIZE;
				break;
			case AT_PHDR:
				auxv->a_un.a_val = elf->textVaddr + elf->ehdr->e_phoff;
				break;
			case AT_PHNUM:
				auxv->a_un.a_val = elf->ehdr->e_phnum;
				break;
			case AT_BASE:
				auxv->a_un.a_val = (unsigned long)linker.text;
				break;
			case AT_ENTRY:
				auxv->a_un.a_val = elf->ehdr->e_entry;
				break;
			
		}
	}

	return esp_start;
	
}	
	
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))
#define ALIGN(k, v) (((k)+((v)-1))&(~((v)-1)))
#define ALIGNDOWN(k, v) ((unsigned long)(k)&(~((unsigned long)(v)-1)))

	
void * load_elf_binary(char *mapped, int fixed, Elf64_Ehdr **elf_ehdr, Elf64_Ehdr **ldso_ehdr)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr, *interp = NULL;
	void *text_segment = NULL;
	void *entry_point = NULL;
	unsigned long initial_vaddr = 0;
	unsigned long brk_addr = 0;
	char buf[128];
	unsigned int mapflags = MAP_PRIVATE|MAP_ANONYMOUS;
        unsigned int protflags = 0;
        unsigned long map_addr = 0, rounded_len, k;
        unsigned long unaligned_map_addr = 0;
        void *segment;
	int i;

	if (fixed)
		mapflags |= MAP_FIXED;
	ehdr = (Elf64_Ehdr *)mapped;
	phdr = (Elf64_Phdr *)(mapped + ehdr->e_phoff);
	entry_point = (void *)ehdr->e_entry;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_INTERP) {
			interp = (Elf64_Phdr *)&phdr[i];
			continue;
		} 
		if (phdr[i].p_type != PT_LOAD)
			continue;
		if (text_segment && !fixed) {
                        unaligned_map_addr
                                = (unsigned long)text_segment
                                + ((unsigned long)phdr[i].p_vaddr - (unsigned long)initial_vaddr);
                        map_addr = ALIGNDOWN((unsigned long)unaligned_map_addr, 0x1000);
                        mapflags |= MAP_FIXED;
                } else if (fixed) {
                        map_addr = ALIGNDOWN(phdr[i].p_vaddr, 0x1000);
                } else {
                        map_addr = 0UL;
                }

	        if (fixed && initial_vaddr == 0)
                	initial_vaddr = phdr[i].p_vaddr;

                /* mmap() freaks out if you give it a non-multiple of pagesize */
                rounded_len = (unsigned long)phdr[i].p_memsz + ((unsigned long)phdr[i].p_vaddr % 0x1000);
                rounded_len = ROUNDUP(rounded_len, 0x1000);
		segment = _mmap2(
                        (void *)map_addr,
                        rounded_len,
                        PROT_READ|PROT_WRITE|PROT_EXEC, mapflags, -1, 0
                );

		if (segment == (void *)-1 || segment == (void *)0) {
			//_printf("mmap2() failed\n");
			Exit(-1);
		}
		_memcpy(
                        fixed ? (void *)phdr[i].p_vaddr:
                        (void *)((unsigned long)segment + ((unsigned long)phdr[i].p_vaddr % 0x1000)),
                        mapped + phdr[i].p_offset,
                        phdr[i].p_filesz
                );	

		if (!text_segment) {
                        *elf_ehdr = segment;
                        text_segment = segment;
                        initial_vaddr = phdr[i].p_vaddr;
                        if (!fixed)
                                entry_point = (void *)((unsigned long)entry_point
                                        - (unsigned long)phdr[i].p_vaddr
                                        + (unsigned long)text_segment);
                }


                if (phdr[i].p_flags & PF_R)
                        protflags |= PROT_READ;
                if (phdr[i].p_flags & PF_W)
                        protflags |= PROT_WRITE;
                if (phdr[i].p_flags & PF_X)
                        protflags |= PROT_EXEC;
                
		if (_mprotect(segment, rounded_len, protflags) < 0) {
		//	_printf("mprotect failed\n");
		//	Exit(-1);
		}

                k = phdr[i].p_vaddr + phdr[i].p_memsz;
                if (k > brk_addr) 
			brk_addr = k;
        }
	if (interp) {
                Elf64_Ehdr *junk_ehdr = NULL;
		char *name = (char *)&mapped[interp->p_offset];
		int fd = _open(name, O_RDONLY);
		uint8_t *map = (uint8_t *)(uintptr_t)_mmap2(0, LINKER_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
		if (map == (void *)MAP_FAILED) {
			//_printf("[STUB] map failed\n");
			Exit(-1);
		}
		entry_point = (void *)load_elf_binary(map, 0, ldso_ehdr, &junk_ehdr);
        }

        if (fixed)
                _brk(ROUNDUP(brk_addr, 0x1000));

        return (void *)entry_point;

}



int parse_and_load_segments(ElfBin_t *elf, stub_meta_t *stub)
{
	unsigned int binary_size = stub->len;
	unsigned long addr = stub->location;
	
	unsigned char *mem = (unsigned char *)addr;
	int fixed = 1;
	int i;
	

	for (i = 0; i < binary_size; i++) {
		mem[i] ^= ((0xD * i) & 0xff);
	}

	elf->ehdr = (Elf64_Ehdr *)mem;
	elf->phdr = (Elf64_Phdr *)(mem + elf->ehdr->e_phoff);

	for (i = 0; i < elf->ehdr->e_phnum; i++) {
		if (elf->phdr[i].p_type == PT_LOAD) {
			if (elf->phdr[i].p_vaddr == 0)
				fixed = 0;
			if (elf->phdr[i].p_offset == 0) {
				elf->textVaddr = elf->phdr[i].p_vaddr;
				elf->textOff = elf->phdr[i].p_offset;
				elf->textSize = elf->phdr[i].p_memsz;
				elf->dataVaddr = elf->phdr[i + 1].p_vaddr;
				elf->dataOff = elf->phdr[i + 1].p_offset;
				elf->dataSize = elf->phdr[i + 1].p_memsz;
			}
		}
	}
	void *entry_point = (void *)load_elf_binary(mem, fixed, &elf->ehdr, &linker.ehdr);
	linker.entry = (unsigned long)entry_point;
	
}


auxv_t * save_auxv(char **envp)
{
        Elf64_Addr *p;
        Elf64_auxv_t *v;
        int count;
        auxv_t *auxv = ALLOCATE(sizeof(auxv_t));

        p = (Elf64_Addr *)envp;
        while (*p != 0)
                ++p;
        ++p;
        for (count = 0, v = (Elf64_auxv_t *)p; v->a_type != AT_NULL; v++)
                count++;
        count++;

        auxv->count = count;
        auxv->size = count * sizeof(*v);
        auxv->vector = ALLOCATE(auxv->size);
        _memcpy((void *)auxv->vector, (void *)p, auxv->size);
        
        return auxv;

}


static inline void set_ld_bind_now(char **) __attribute__((always_inline));

/*
 * This function will do equiv of putenv("LD_BIND_NOW=1"); although
 * not as elequently. If LD_BIND_NOW isn't already in env list
 * we overwrite an old unimportant variable 'OLDPWD', by modifying
 * its pointer to a new area that contains string 'LD_BIND_NOW=1'
 */
static inline  void set_ld_bind_now(char **envp)
{
        char **s, **old = envp;
        char *p;
	int i;
        unsigned long base = ((unsigned long)envp & ~0xfffff);
        unsigned long masked;

        for (i = 0, s = envp; s != NULL; i++, s++) {
                char *t = *s;
                masked = (long)t & ~0xfffff;
                /* 
		 * This will only be true if we're past the last
		 * envp pointer
		 */
		if (masked != base) {
			break;
			/* 
			 * Locate OLDPWD and replace it with LD_BIND_NOW=1
			 */
			for (s = old; s != NULL; s++) {
				t = *s;
				if (!_strncmp(t, "OLDPWD=")) {
					char *new = ALLOCATE(64);
					_strcpy(new, "LD_BIND_NOW=1");
					*s = new;
					break;
				}
			}
                        break;
		}
		
		/*
		 * If LD_BIND_NOW is already in environment list
		 * make sure it is set to 1
		 */
		if (!_strncmp(t, "LD_BIND_NOW=")) {
			*(char *)(_strchr(t, '=') + 1) = '1';
			break;
		}
        }

}

_start()
{
	ElfBin_t program;
	Elf64_Addr rsp;

        /* get argc */
	int argc;
        int i;
        long *args;
	long *envs;
	long *rbp;

	unsigned char *m = (unsigned char *)STUB_META_LOCATION;
	unsigned int metaVaddr;
	stub_meta_t stubdata;
	struct argdata ap;

        /* Extract argc from stack */
        asm __volatile__("mov 8(%%rbp), %%rcx " : "=c" (argc));
     
        /* Extract argv from stack */
        asm __volatile__("lea 16(%%rbp), %%rcx " : "=c" (args));
	
	
	asm __volatile__("lea 40(%%rbp), %%rcx " : "=c" (rbp));
	
	rbp += ((argc * sizeof(void *)) >> 3);
	envs = (long *)rbp;

        /* Setup argv pointer */
        char **argv = (char **)&args[0];

	/* Setup envp pointer */
	char **envp = (char **)&envs[0];
	
	/* Forces strict linking for the RO relocation feature */
	//set_ld_bind_now(envp);

	ap.saved_auxv = save_auxv(envp);
	save_stack_data(argc, argv, envp, &ap);
	
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)STUB_BASE;
	
	metaVaddr = ehdr->e_flags == 1 ? 0 : ehdr->e_flags ^ META_XOR_BITS;

	if (metaVaddr == 0) {
#if DEBUG
		_printf("[!] This is a stub with no program payload... why are you executing this?\n");
#endif
		Exit(0);
	}

	_memcpy((void *)&stubdata, (void *)(long)metaVaddr, sizeof(stub_meta_t));

	parse_and_load_segments(&program, &stubdata);
	
	rsp = build_auxv_stack(&program, &ap);
	
	SET_STACK_AND_JMP(rsp, linker.entry);
	Exit(0);


}

		

