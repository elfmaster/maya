#include "maya.h"

	
int check_elf64_integrity(ElfBin_t *elf, elfspec_t *specs)
{
	Elf64_Ehdr *ehdr = elf->ehdr;
	Elf64_Phdr *phdr = elf->phdr;
	Elf64_Shdr *shdr = elf->shdr;
	uint8_t *mem = elf->mem;
	char *StringTable;
	int i, dyn, pt_load_count, symtab = 0;
	int ret = 0;
	int eh_frame = 0;

	if (elf == NULL)
		return -1;

	if (ehdr->e_type != ET_EXEC) {
		specs->exec_type = SPEC_FAILED;
		ret = 1;
	}
	if (ehdr->e_machine != EM_X86_64) {
		specs->mach_type = SPEC_FAILED; 
		ret = 1;
	}
	if (ehdr->e_shoff == 0 || ehdr->e_shoff > elf->size) {
		specs->shdr_table = SPEC_FAILED;
		ret = 1;
	}

	if (ehdr->e_shnum == 0 || ehdr->e_shnum > 64) {
		specs->shdr_count = SPEC_FAILED;
		ret = 1;
	}
	
	for (pt_load_count = 0, dyn = 0, i = 0; i < ehdr->e_phnum; i++) {
		switch(phdr[i].p_type) {
			case PT_DYNAMIC:
				dyn++; 
				break;

			case PT_LOAD:
				pt_load_count++;
				if ((phdr[i].p_flags & PF_X) && phdr[i].p_offset == 0)
					if (phdr[i].p_flags & PF_W) {
						specs->text_perms = SPEC_FAILED;
						ret = 1;
					}
				if (phdr[i].p_align && (phdr[i].p_offset ^ phdr[i].p_vaddr) & (phdr[i].p_align - 1)) {
					specs->phdr_align = SPEC_FAILED;
					ret = 1;
				}
				break;

			case PT_GNU_EH_FRAME:
				eh_frame++;
				break;
				
		}
	}
	if (eh_frame == 0 && specs->shdr_table != SPEC_FAILED) {
		StringTable = (char*)&mem[shdr[ehdr->e_shstrndx].sh_offset];
		for (i = 0; i < ehdr->e_shnum; i++)
			if (!strcmp(".eh_frame", &StringTable[shdr[i].sh_name]))
				eh_frame++;
	}

	if (eh_frame == 0) 
		specs->eh_frame = SPEC_FAILED;
			
	if (pt_load_count < 2 || pt_load_count > 2) {
		specs->pt_load = SPEC_FAILED;
		ret = 1;
	}
	
	if (opts.layers == MAYA_L0_PROT)
		return ret;

	for (symtab = 0, i = 0; i < ehdr->e_shnum; i++)
		if (shdr[i].sh_type == SHT_SYMTAB)
			symtab++;

	if (!symtab && !eh_frame) {
		specs->symtab = SPEC_FAILED;
		ret = 1;
	}
					
	return ret;
}

int verify_elf_requirements(ElfBin_t *bin)
{
	
	elfspec_t specs;
	int ret;

	if ((ret = check_elf64_integrity(bin, &specs)) < 0)
		return -1;
	if (ret > 0)
		fprintf(stderr, "[ELF INTEGRITY FAILED]: Executable '%s' is not fit for protection as it fails to meet required specs\n", bin->path);
	if (specs.exec_type == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: Executable type is not ET_EXEC\n");
	if (specs.mach_type == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: Unsupported architecture (Must be x86_64)\n");
	if (specs.shdr_table == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: Non-existent or invalid section header table\n");
	if (specs.shdr_count == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: Invalid section header index count\n");
	if (specs.text_perms == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: Text segment permissions should be READ+EXECUTE only\n");
	if (specs.phdr_align == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: Loadable segment offsets/vaddr must be congruent with alignment value\n");
	if (specs.pt_load == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: Only two loadable segments (PT_LOAD's) may exist. Maya requires no less, and no more\n");
	if (specs.symtab == SPEC_FAILED)
		fprintf(stderr, "[ELF FAILURE]: No symbol table found for local functions. Maya requires symbol table for -l1/-2 protection\n");

	if (ret > 0)
		return SPEC_FAILED;
	return SPEC_PASSED;
}

