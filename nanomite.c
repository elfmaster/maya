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

