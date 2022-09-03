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

#include "maya.h"

#define AVERAGE_INSTRUCTION_LEN 5
#define CALL_SIZE 5

#define MAX_INST_COUNT 5000000

#define RET_BYTE 0xC3
#define IRET_BYTE 0xCF
#define LRET_BYTE 0xCB

uint32_t get_target_operand(ud_t *ud_obj, enum ud_mnemonic_code mnemonic, uint32_t branchSite)
{
	uint32_t targetVaddr = 0, offset;
	const uint8_t *code;
	uint8_t *p;
	
	switch (mnemonic) {
		case UD_Ijno:
		case UD_Ijns:
		case UD_Ijnz:
		case UD_Ijnp:
			code = ud_insn_ptr(ud_obj);
			p = (uint8_t *)&code[1];
			offset = (uint32_t)(uint8_t)p[0];
			targetVaddr = branchSite + offset + 2;
			break;
		case UD_Ijmp:
			code = ud_insn_ptr(ud_obj);
			p = (uint8_t *)&code[1];
			offset = (p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24));
			targetVaddr = branchSite + offset + 5; 
			break;
		case UD_Icall:
			code = ud_insn_ptr(ud_obj);
			p = (uint8_t *)&code[1];
			offset = (p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24));
			targetVaddr = branchSite + offset + 5;
			break;
	}
	
	return targetVaddr;
}
	
static void init_disas(ud_t *ud_obj, ElfBin_t *bin)
{
	ud_init(ud_obj);
        ud_set_vendor(ud_obj, UD_VENDOR_AMD);
        ud_set_mode(ud_obj, 64);
        ud_set_input_buffer(ud_obj, bin->mem, bin->origTextSize);
        ud_set_syntax(ud_obj, UD_SYN_ATT);
}

int generate_code_map(codemap_t *map, ElfBin_t *bin)
{
	struct timeval tv;
	ud_t ud_obj;
	uint8_t *p;
	int i;	
	unsigned int nanocount = 0;

	init_disas(&ud_obj, bin);
	
	map->instdata = malloc(sizeof(instdata_t) * MAX_INST_COUNT);
	
	for (i = 0; i < MAX_INST_COUNT; i++) {
		map->instdata[i].ret = 0;
		map->instdata[i].jmp = 0;		
		map->instdata[i].call = 0;
		map->instdata[i].nanomite = 0;
	}

	for (map->instcount = 0; ud_disassemble(&ud_obj); map->instcount++) {
 		
       		map->instdata[map->instcount].len = ud_insn_len(&ud_obj);
		map->instdata[map->instcount].offset = ud_insn_off(&ud_obj);
        	map->instdata[map->instcount].string = ud_insn_asm(&ud_obj);
		map->instdata[map->instcount].hexbytes = ud_insn_ptr(&ud_obj);
		map->instdata[map->instcount].vaddr = bin->textVaddr + map->instdata[map->instcount].offset;
		map->instdata[map->instcount].mnemonic = ud_insn_mnemonic(&ud_obj);
		
		/*
		 * Is the instruction a return? Or another type of branch?
		 */
		
		if (nanocount == MAX_NANOMITES)
			continue;

		switch(map->instdata[map->instcount].mnemonic) {
			case UD_Iret:
			case UD_Iretf:
				map->instdata[map->instcount].ret++;
				break;
			case UD_Ijmp:
				if (map->instdata[map->instcount].hexbytes[0] != 0xe9)
					break;
			case UD_Ijno:
			case UD_Ijnz:
			case UD_Ijns:
			case UD_Ijnp:
				map->instdata[map->instcount].jmp++;
				gettimeofday(&tv, NULL);
				if ((tv.tv_usec & 7) == 0) {
					nanocount++;
					map->instdata[map->instcount].nanomite++;
					map->instdata[map->instcount].emulate.branch_target = 
					get_target_operand(&ud_obj, map->instdata[map->instcount].mnemonic, map->instdata[map->instcount].vaddr);
				}
				break;
			case UD_Icall:
				map->instdata[map->instcount].call++;
				gettimeofday(&tv, NULL);
				if ((tv.tv_usec & 7) == 0) {
					if (map->instdata[map->instcount].hexbytes[0] != 0xe8)
						break;
					nanocount++;
					map->instdata[map->instcount].nanomite++;
					map->instdata[map->instcount].emulate.branch_target = 
					get_target_operand(&ud_obj, map->instdata[map->instcount].mnemonic, map->instdata[map->instcount].vaddr);
					map->instdata[map->instcount].emulate.retaddr = map->instdata[map->instcount].vaddr + CALL_SIZE;
				}
				break;
		}
		
		

	}
	
	return 0;
}

	

	












