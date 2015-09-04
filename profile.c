/*
 * cprofile.c - contains the code for profiling the control flow
 * and the quirks that each functinon might contain (i.e tailcall optimizations, multiple rets etc.)
 */

#include "maya.h"

void swap(struct profile_list *, int, int);
struct profile_list *qsort_list(struct profile_list *, int, int);
struct profile_list * add_function(struct profile_list **, uint32_t, size_t);
struct profile_list *sort_list_by_value(struct profile_list *);
int item_count = 0;
/*
 * The following functions will sort the linked list
 * by smallest to largest function address. Don't
 * run the sort after all other values have been filled
 * out in the nodes though, otherwise things will get
 * mixed up.
 */
int get_lval(struct profile_list *head, int l)
{
	while(head && l) {
        	head = head->next;
        	l--;
    	}
    	if (head != NULL)
        	return head->func.vaddr;
   
     	return -1;
}

struct profile_list *sort_list_by_value(struct profile_list *head)
{
	struct profile_list *tmp = head;
    	uint32_t n = 0;

    	while (tmp) {
        	n++;
        	tmp = tmp->next;
    	}

    	head = qsort_list(head, 0, n);
    	return head;
}

struct profile_list *qsort_list(struct profile_list *head, int l, int r)
{
	int i, j, jval, pivot;
    	
	i = l + 1;
    	if (l + 1 < r) {
        	pivot = get_lval(head, l);
        	for (j = l + 1; j <= r; j++) {
            		jval = get_lval(head, j);
            		if (jval < pivot && jval != -1) {
                		swap(head, i, j);
                		i++;
            		}
        	}
       
		swap(head, i - 1, l);
       	 	qsort_list(head, l, i);
        	qsort_list(head, i, r);
    	}

    return head;
}

void swap(struct profile_list *head, int i, int j)
{
	struct profile_list *tmp = head;
    	unsigned int tmpival;
    	unsigned int tmpjval;
    	unsigned int tmps1val;
	unsigned int tmps2val;
	int ti = i;
    
	while(tmp && i) {
        	i--;
        	tmp = tmp->next;
    	}
    
	tmpival = tmp->func.vaddr;
    	tmps1val = tmp->func.size;
	tmp = head;
 	while(tmp && j) {
        	j--;
        	tmp = tmp->next;
    	}

    	tmpjval = tmp->func.vaddr;
	tmps2val = tmp->func.size;
    	tmp->func.vaddr = tmpival;
	tmp->func.size = tmps1val;

    	tmp = head;
    	i = ti;
    	while(tmp && i) {
        	i--;
        	tmp = tmp->next;
    	}
    	tmp->func.vaddr = tmpjval;
	tmp->func.size = tmps2val;
}

struct profile_list * add_function(struct profile_list **head, uint32_t vaddr, size_t size)
{
	struct profile_list *tmp = (struct profile_list *)malloc(sizeof(struct profile_list));
	struct profile_list *current = *head;
	char *p;
	
	while (current) {
		if (current->func.vaddr == vaddr)
			return *head;
		current = current->next;
	}

	if (tmp == NULL) 
		return NULL;
	
	item_count++;
	tmp->prof.multiret = 0;
	tmp->prof.tailcall = 0;
	tmp->prof.interval = 0;
	tmp->func.callcount = 0;
	tmp->func.retlocation = (uint64_t *)heapAlloc(sizeof(uint64_t) * 2);
	tmp->func.retcount = 0;
	tmp->func.vaddr = vaddr;
	tmp->func.size = size;
	tmp->next = *head;
	*head = tmp;
	
	return *head;
}


uint32_t construct_code_profile(ElfBin_t *bin, codemap_t *codemap, cprofile_t *profile)
{
	struct fde_func_data *fndata, *fdp;
	size_t fncount;
	struct profile_list *listp, *current;
	uint32_t i, j, b;
	uint32_t target, offset;
	int use_fde = 0;

	profile->items = 0;
	/*
	 * Our 1st step to creating a code profile of a binary
	 * is to locate every function, which we originally did
	 * by finding every call instruction. We may still use
	 * this method if the binary does not have an eh_frame
	 * section, but otherwise it is not necessary since we
	 * can look at the stack unwinding data in the ever so
	 * esoteric .eh_frame section of a binary.
	 */
	
	if (phdr_is_valid(bin, PT_GNU_EH_FRAME)) {
		use_fde++;
		goto dwarves;
	}

	printf("[!] No eh_frame segment found, using disassembly analysis for control flow\n");

disas:
	/*
	 * The disassemble method of control flow analysis is prone to
	 * false positives, and hopefully we won't have to execute this
	 * code. Instead we either use a symbol table or eh_frame to
	 * get the function info
	 */
	for (i = 0; i < codemap->instcount; i++) {
		switch(codemap->instdata[i].mnemonic) {
			case UD_Icall:
				if (codemap->instdata[i].hexbytes[0] != 0xe8) // currently only handle relative calls
					continue;

				offset = codemap->instdata[i].hexbytes[1] + (codemap->instdata[i].hexbytes[2] << 8) +
			 		(codemap->instdata[i].hexbytes[3] << 16) + (codemap->instdata[i].hexbytes[4] << 24);
				target = codemap->instdata[i].vaddr + offset + 5;
			
				codemap->instdata[i].call_target = target; 

				if (!in_range_by_section(bin, ".text", target))
					continue;
				
				profile->items++;
				if ((listp = add_function(&profile->list_head, target, 0)) == NULL) {
					printf("[!] Error, add_function() failed when building code profile\n");
					return -1;
				}
		}

	}
        for (current = listp = sort_list_by_value(listp); current != NULL; current = current->next) {
        	if (current->next == NULL) {
        		current->func.name = (char *)(uintptr_t)xfmtstrdup("sub_%x", current->func.vaddr);
               		break;
        	}
                current->func.size = current->next->func.vaddr - current->func.vaddr;
                current->func.name = (char *)(uintptr_t)xfmtstrdup("sub_%x", current->func.vaddr);
        }

	
dwarves:
	
	printf("[+] Using .eh_frame data to build a map of function calls\n");
	if ((fncount = get_all_functions(bin->path, &fndata)) < 0) {
		printf("[!] get_all_functions() failed, resorting to disassembly analysis\n");
		use_fde = 0;
		goto disas;
	}
	profile->items = fncount;
	fdp = (struct fde_func_data *)fndata;	
	for (i = 0; i < fncount; i++) {
	 	if ((listp = add_function(&profile->list_head, fdp->addr, fdp->size)) == NULL) {
                	printf("[!] Error, add_function() failed when building code profile\n");
                        return -1;
                } 
		fdp++;
	}

	for (current = listp = sort_list_by_value(listp); current != NULL; current = current->next) {
		if (current->next == NULL) {
			current->func.name = xfmtstrdup("%s_0x%x", get_section_name(bin, current->func.vaddr), current->func.vaddr);
			break;
		}
			current->func.name = xfmtstrdup("%s_0x%x", get_section_name(bin, current->func.vaddr), current->func.vaddr);
	}

	if (opts.verbose)
		for (current = listp; current != NULL; current = current->next) 
			printf("[PROFILE] Discovered-> Function: %s\t Vaddr: %x\t size: %x\n", current->func.name, current->func.vaddr, current->func.size);
	
	/*
	 * How many times is each function called?
	 * How many ret instructions does each function have?
	 * Lets profile the functions personality a bit... 
	 * get to know each one, get on friendly terms.
	 */
	for (i = 0; i < codemap->instcount; i++) {
                switch(codemap->instdata[i].mnemonic) {
                        case UD_Icall:
                                if (codemap->instdata[i].hexbytes[0] != 0xe8) // currently only handle relative calls
                                        continue;

                                offset = codemap->instdata[i].hexbytes[1] + 
					(codemap->instdata[i].hexbytes[2] << 8) +
                                        (codemap->instdata[i].hexbytes[3] << 16) + 
					(codemap->instdata[i].hexbytes[4] << 24);
                                
				target = codemap->instdata[i].vaddr + offset + 5;
                                codemap->instdata[i].call_target = target;
				
                                if (!in_range_by_section(bin, ".text", target))
                                        continue;
	
				for (current = listp; current != NULL; current = current->next) {
					if (current->func.vaddr == target) {
						current->func.callcount++;
						if (opts.verbose)
							printf("[PROFILE] call -> Function %s called %d %s\n", 
							current->func.name, current->func.callcount, 
							current->func.callcount > 1 ? "times" : "time");
						break;
					} 
				}
				break;
			case UD_Iret:
			case UD_Iretf:
				/*
				 * If we hit a ret instruction, what function is it in?
				 */
				for (current = listp; current != NULL; current = current->next) {
					if (codemap->instdata[i].vaddr >= current->func.vaddr && 
					    codemap->instdata[i].vaddr < current->func.vaddr + current->func.size) {
						if (current->func.retcount > 0)
							current->func.retlocation = realloc(current->func.retlocation,
						        				   (current->func.retcount + 2) * sizeof(uint64_t));
						current->func.retlocation[current->func.retcount] = codemap->instdata[i].vaddr;
						current->func.retcount++; 
						if (current->func.retcount > 1)
							current->prof.multiret = 1;
						if (opts.verbose)
							printf("[PROFILE] ret -> found ret[at %lx] instruction in function %s\n", 
								codemap->instdata[i].vaddr, current->func.name);
						
						break;
					}
				}

			
		}			
	}
	
	for (current = listp; current != NULL; current = current->next) {
		if (current->func.callcount >= 10) {
			printf("Setting prof.interval to %d\n", FCALL_INTERVAL(current->func.callcount));
			current->prof.interval = FCALL_INTERVAL(current->func.callcount);
			if (opts.verbose) 
				printf("[PROFILE] interval-> Function %s will be re-encrypted every %d times it is called\n", 
					current->func.name, current->prof.interval);
		}
	} 

	return 0;
}

