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

/*
 * We build the nanomite structs
 * and from elf.c they are injected
 * into knowledge.nanomites within
 * tracer.o
 */
void construct_nanomites(codemap_t *map, nanomite_t *nanomite, unsigned int *count)
{
	int i, c = 0;
	nanomite_t *np = nanomite;
	
	for (i = 0; i < map->instcount; i++) {
		if (map->instdata[i].nanomite) {
			c++;
			if (map->instdata[i].call) {
				np->type = NANOMITE_CALL;
				np->vaddr = map->instdata[i].emulate.branch_target;
				np->retaddr = map->instdata[i].emulate.retaddr;
				np->site = map->instdata[i].vaddr;
				np->size = map->instdata[i].len;
				np++;
			} else
			if (map->instdata[i].jmp) {
				np->type = NANOMITE_JMP;
				np->vaddr = map->instdata[i].emulate.branch_target;
				np->site = map->instdata[i].vaddr;
				np->size = map->instdata[i].len;
				np++;
			}
		}
	}
	*count = c;
}

