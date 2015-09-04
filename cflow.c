#include "maya.h"

/*
 * Currently we only disassemble relative calls
 * and since we don't do instruction length parsing
 * we validate a call is really a call instruction by
 * computing its target offset into an address and seeing
 * if it is within the bounds of the executables text
 * segment (Not section). Since calls to the .plt (Which
 * we don't operate on yet) will need to be handled
 * once I incorperate cflow into shared libraries as well
 * which is where it is really most pertinent
 */

#define CALL_INSTR_BYTE 0xE8

int generate_local_cflow_data(ElfBin_t *exe, maya_cflow_t *cflow)
{
	uint8_t *mem;
	Elf64_Shdr *shdr = exe->shdr;
	Elf64_Phdr *phdr = exe->phdr;
	int i;

	unsigned int textLen = get_section_size(exe, ".text");
	unsigned int textOff = get_section_offset(exe, ".text"); 
	unsigned int textVaddr = get_section_vaddr(exe, ".text");
	unsigned int rlo = exe->textVaddr;
	unsigned int rhi = exe->textVaddr + exe->origTextSize;
	unsigned int targetOff, targetAddr;
	
	/*
	 * Find every call instruction and use that info to
	 * determine where the 'ret' instruction exists in the
	 * called function, and what the valid return address
	 * should be.
	 */
	exe->cflow_count = 0;
	for (mem = &exe->mem[textOff], i = 0; i < textLen; i++) {
		if (mem[i] != CALL_INSTR_BYTE)
			continue;
		targetOff = (mem[i + 1] + (mem[i + 2] << 8) + (mem[i + 3] << 16) + (mem[i + 4] << 24));	
		targetAddr = textVaddr + i + targetOff + 5; 
		if (targetAddr >= rlo && targetAddr <= rhi) { 
			if (in_range_by_section(exe, ".plt", targetAddr)) {
				/*
				 * NOTE: The target function is actually a PLT stub  
				 * so we mark this cflow entry as PLT by initializing
			         * it as 0xdeadc0de, and let tracer.o store the breakpoint
				 * on the necessary shared library during runtime.
				 */
				cflow[exe->cflow_count].retLocation = 0xDEADC0DE;
				cflow[exe->cflow_count].validRetAddr = textVaddr + i + 5;
#ifdef DEBUG
				printf("CONTROL FLOW(PLT): <ret:0x%lx -> 0x%lx>\n", cflow[exe->cflow_count].retLocation, cflow[exe->cflow_count].validRetAddr);
#endif
				exe->cflow_count++;
				continue;
			}
			/*
			 * If we made it here, then the call is to a local function
			 * so we can build the CFI data with the information we have.
			 */
			cflow[exe->cflow_count].retLocation = targetAddr + get_symbol_size_by_addr(exe, targetAddr) - 1; // address of where the funcs ret will be
			cflow[exe->cflow_count].validRetAddr = textVaddr + i + 5; // the return value is 5 bytes past the call
			
#ifdef DEBUG
			printf("CONTROL FLOW: <ret:0x%lx -> 0x%lx>\n", cflow[exe->cflow_count].retLocation, cflow[exe->cflow_count].validRetAddr); 
		
#endif
			exe->cflow_count++;
		}	 
		
	}

}

