#include "maya.h"

int ExtractArgs(char ***argvp, char *delim, char *s)
{

        int tokens;
        char *t, *snew;

        snew = s + strspn(s, delim);
        if ((t = calloc (strlen (snew) + 1, sizeof (char))) == NULL) {
                *argvp = NULL;
                tokens = -1;
        }
        else
                strcpy(t, snew);

        if (strtok(t, delim) == NULL)
                tokens = 0;
        else
                for (tokens = 1; strtok(NULL, delim) != NULL; tokens++);

        if ((*argvp = calloc(tokens + 1, sizeof(char *))) == NULL)
                tokens = -1;
        else
        if (tokens > 0) {
                bzero(t, strlen(snew));
                strcpy(t, snew);
                **argvp = strtok(t, delim);
                int i;
                for (i = 1; i < tokens + 1; i++)
                        *((*argvp) + i) = strtok(NULL, delim);
        }
        else
                **argvp = NULL;

        return tokens;

}

#define STUB_PATH "./stub"

/*
 * Move these somewhere other than global
 * XXX must organize this sooner than later.
 */
maya_modes_t maya_mode;

int main(int argc, char **argv)
{	
	ElfBin_t target, tracer;
	codemap_t codemap;
	int c, i;

	if (argc < 4) {
usage:
		printf("\n***-=[ Maya's Veil-- Software protection agent: V.0.1 Alpha ]=-***\n");
		printf("\tBrought to you by the Bitlackeys in 2014\n\n");
		printf("Usage: %s [-l0/-l1/-l2] [-pCEPfcnosv] [-e <executable>]\n", argv[0]);
		printf("-l0	No encryption layer\n");
		printf("-l1	Layer 1 protection only (Function Runtime protection)\n");
		printf("-l2	Layer 2 & layer 1 protection (Advanced runtime protection)\n");
		printf("-l3	Layer 3 + layer 2 & 1 protection (Additional static + advanced runtime: Recommended)\n");
		printf("\n---> [Extended anti-tamper options]\n\n");
		printf("-h	Heap encryption with Maya memory allocator: (For key storage etc: Recommended)\n");
		printf("-p      Process memory protection (Uses prctl() to further prevent memory dumping and tracing)\n");
		printf("-P	Additional process memory protection (Uses prctl() and /proc analysis): /proc analysis slows down performance immensely.\n");
		printf("-f	Fingerprint the host so that binary runs only on this system\n"); 
		printf("-c	Control flow integrity (Anti Exploitation): Prevents ROP attacks\n");
		printf("-n	Nanomites Feature; Emulates about 50%% of a programs branch instructions (Never decrypts them)\n");
		printf("\n---> [Extended obfuscation features]\n\n");
		printf("-o	Obfuscate symbol table and sections (VS. Discarding them with -s): Only effective with -l0/-l1/-l2\n");
		printf("-s	Strip symbol table and section table (Recommended over -o): Only effective with -l0/-l1/-l2\n");
		printf("\n---> [Extended protection phase options]\n\n");
		printf("-C	Complete control flow analysis of binary to generate a more efficient and powerful runtime engine\n");
		printf("-E	Enhance maya runtime engine for speed (Slightly less secure, 100%% faster performance)\n");
		printf("-S	Skip all ELF binary integrity checks and force an attempt at protecting a binary\n");
		printf("-v	Verbose\n\n");
		exit(0);
	}
	
	memset(&opts, 0, sizeof(opts));
	if (!strcmp((char *)argv[1], "-l1")) 
		opts.layers = MAYA_L1_PROT;
	else
	if (!strcmp((char *)argv[1], "-l2")) 
		opts.layers = MAYA_L2_PROT;
	else 
	if (!strcmp((char *)argv[1], "-l0"))
		opts.layers = MAYA_L0_PROT;
	else	
	if (!strcmp((char *)argv[1], "-l3")) {
		opts.layers = MAYA_L2_PROT;
		opts.l3++;
	}
	else
		goto usage;
	
	while ((c = getopt(argc-1, &argv[1], "SPpCrnfvcsoe:")) != -1) {
		switch(c) {
			case 'C':
				opts.cflow_profile++;
				break;
			case 'r':
				opts.ro_relocs++;
				break;
			case 'n':
				if (opts.layers)
					opts.nanomites++;
				break;
			case 'f':
				opts.fingerprint++;
				break;
			case 'v':
				opts.verbose++;
				break;
			case 'e':
				target.path = strdup(optarg);
				break;
			case 'c':
				if (opts.layers)
					opts.cflow++; /* Anti ROP */
				break;
			case 's':
				opts.strip++;
				break;
			case 'o':
				opts.obfuscate++;
				break;
			case 'S':
				opts.skipverify++;
				break;
			default:
				printf("Unknown option\n");
				exit(0);
		}
	}
	
	if (opts.strip && opts.obfuscate) {
		fprintf(stderr, "[?] Option -s and -O cannot be used together!\n\n");
		goto usage;
	}
	/*
	 * ZERO OUT maya_mode_t struct
	 */
	memset((maya_modes_t *)&maya_mode, 0, sizeof(maya_modes_t));
	maya_mode.antidebug = 1;
	printf("\n\n"); 
	
	if (opts.cflow_profile) 
		maya_mode.fnprofile++;

	if (opts.ro_relocs)
		maya_mode.ro_relocs++;

	switch (opts.layers) {
		case MAYA_L0_PROT:
			printf("[MODE] Layer 0: Anti-debugging/anti-code-injection protection\n");
			maya_mode.layer0++;
			break;
		case MAYA_L1_PROT:
			printf("[MODE] Layer 1: Anti-debugging/anti-code-injection, runtime function level protection\n");
			maya_mode.layer1++;
			break;
		case MAYA_L2_PROT:
			printf("[MODE] Layer 2: Anti-debugging/anti-code-injection, runtime function level protection, and outter layer of encryption on code/data\n");
			maya_mode.layer2++;
			break;
		case MAYA_L3_PROT: // not yet supported
			maya_mode.layer3++;
			break;
	}
	
	if (opts.cflow) {
		printf("[MODE] CFLOW ROP protection, and anti-exploitation\n");
		maya_mode.antiexploit++;
	}
	if (opts.nanomites) {
		printf("[MODE] NANOMITES: Randomly selected branch emulation, is turned on\n");
		maya_mode.nanomites++;
	}
	if (opts.fingerprint) {
		printf("[MODE] FINGERPRINT: Host system fingerprinting to bind executable is turned on\n");
		maya_mode.fingerprint++;
	}
	
	printf("\n");

	/*
	 * tracer.o is the brain that we inject into the protected executable.
	 * It is the brain it is the protection, it is the way... forward.
	 * lulz ... elfmaster 2014
	 */
	if (loadElf("./tracer.o", &tracer, PROT_READ|PROT_WRITE, MAP_PRIVATE) < 0) {
		fprintf(stderr, "[!] loadElf() failed on ./tracer.o: %s\n", strerror(errno));
		exit(-1);
	}
	
	if (loadElf(target.path, &target, PROT_READ|PROT_WRITE, MAP_PRIVATE) < 0) {
		fprintf(stderr, "[!] loadElf() failed on %s: %s\n", target.path, strerror(errno));
		exit(-1);
	}
	
	if (!opts.skipverify) {
		if (verify_elf_requirements(&target) == SPEC_FAILED) {
			fprintf(stderr, "[!] Unable to protect file: %s\n", target.path);
			exit(0);
		}
	}

	int ret = check_symtab(&target);
	printf("ret = %d\n", ret);
	if (ret == 0)
		opts.nosymtab = 1;
	
	if (opts.nosymtab) 
		printf("[!] No .symtab found\n");
		
	if (generate_code_map(&codemap, &target) < 0) {
		fprintf(stderr, "[!] generate_code_map() failed\n");
		exit(-1);
	}
	
	target.codemap = (codemap_t *)&codemap;
	

	if (opts.nanomites) {
		target.nanomites = (nanomite_t *)malloc(sizeof(nanomite_t) * MAX_NANOMITES);
		if (target.nanomites == NULL) {	
			perror("malloc");
			exit(-1);
		}
			
		construct_nanomites(&codemap, target.nanomites, &(target.nanocount));
		
		if (opts.verbose) {
			printf("[+] NanoMite listing...\n");
			for (i = 0; i < target.nanocount; i++)
				printf("[nanomite] Site: %lx target: %lx\n", target.nanomites[i].site, target.nanomites[i].vaddr);
		}

	}
	/* Build profile on control flow and function size */
	if (opts.cflow_profile) {
		printf("[+] Performing control flow analysis for intelligent protection decision making\n");
		construct_code_profile(&target, &codemap, &target.cprofile);
	
	}

	if (opts.cflow) {
		printf("[+] Generating control flow data\n");
		generate_local_cflow_data(&target, (maya_cflow_t *)&maya_cflow[0]);
	}
	
	if (opts.fingerprint) {
		printf("[+] Generating system fingerprint for protected binary\n");
		if (generate_fingerprint(fingerprint) < 0) {
			fprintf(stderr, "[!] Unable to generate system fingerprint\n");
			exit(-1);
		}
	}

	
	/*
	 * We apply encryption before injecting the brain (tracer.o) which
	 * handles the decryption engine etc.
	 */
	if (opts.layers > MAYA_L0_PROT)
		apply_code_obfuscation(&target, &tracer);
	/*
	 * Fixup relocations on tracer.o before injecting it into the host
	 */
	RelocateCode(&tracer, &target);
	/*
	 * Inject tracer.o (The intelligent routine for crypto decoding and anti-debugging)
	 * into the target executable by extending the targets text in reverse.
	 */
	if (injectObject(&tracer, &target) < 0) {
		fprintf(stderr, "[!] injectObject() failed on %s\n", target.path);
		exit(-1);
	}
	
	
	if (opts.l3) {
		char *path = (char *)(uintptr_t)xfmtstrdup("%s.maya", target.path);
		
		unloadElf(&target);

		ElfBin_t final, stub;
		
		if (loadElf(path, &final, PROT_READ|PROT_WRITE, MAP_PRIVATE) < 0) {
                	fprintf(stderr, "[!] loadElf() failed on %s: %s\n", final.path, strerror(errno));
                	exit(-1);
		}
		
	
		if (loadElf(STUB_PATH, &stub, PROT_READ|PROT_WRITE, MAP_PRIVATE) < 0) {
			fprintf(stderr, "[!] loadElf() failed on %s: %s\n", STUB_PATH, strerror(errno));
			exit(-1);
		}
		
		add_layer_3(&final, &stub);
		
        }
	
	

}

