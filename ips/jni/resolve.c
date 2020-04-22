#include "resolve.h"


//get function by library name and symbol
//get function by library name and pattern...
//get library base...

unsigned long   symtab;
unsigned long   strtab;
int             nchains;

void *text_base;
int text_size;

int locate_text_segment(int pid, void *base){
	//all of these read_data calls should really read from a file...
	//and add the offsets we get from that to the base address in memory
	my_elf_hdr *hdr = malloc(sizeof(my_elf_hdr));
	my_pht_entry *pht = malloc(sizeof(my_pht_entry));
	my_sht_entry *sht = malloc(sizeof(my_sht_entry));	

	read_data(pid, base, hdr, sizeof(my_elf_hdr));
/*	
	printf("[entrypoint] e_startadr=%08x\n", hdr->e_startadr);
	printf("[program header table offset] e_phoff=%08x\n", hdr->e_phoff);
	printf("[program header table # of entries] e_phnum=%04x\n", hdr->e_phnum);
	printf("[program header table entry size] e_phentsize=%04x\n", hdr->e_phentsize);
	printf("[program header table total size] %d\n", hdr->e_phnum * hdr->e_phentsize);
	printf("[program header table location] start=%08x, end=%08x\n", hdr->e_phoff + base, hdr->e_phoff + base + (hdr->e_phnum * hdr->e_phentsize));
	
	printf("[section header table offset] e_shoff=%08x\n", hdr->e_shoff);
	printf("[section header table # of entries] e_shnum=%04x\n", hdr->e_shnum);
	printf("[section header table entry size] e_shentsize=%04x\n", hdr->e_shentsize);
	printf("[section header table total size] %d\n", hdr->e_shnum * hdr->e_shentsize);
	printf("[section header table location] start=%08x, end=%08x\n", hdr->e_shoff + base, hdr->e_shoff + base + (hdr->e_shnum * hdr->e_shentsize));

	printf("\n");
*/
	int i;
	void *table_base = hdr->e_phoff + base;
	for (i=0; i< hdr->e_phnum; i++){
		read_data(pid, table_base, pht, hdr->e_phentsize);
/*
		printf("[program header table entry(%d)] p_type=%08x\n", i, pht->p_type);
		printf("[program header table entry(%d)] p_offset=%08x\n", i, pht->p_offset);
		printf("[program header table entry(%d)] p_vaddr=%08x\n", i, pht->p_vaddr);
		printf("[program header table entry(%d)] p_paddr=%08x\n", i, pht->p_paddr);
		printf("[program header table entry(%d)] p_filesz=%08x\n", i, pht->p_filesz);
		printf("[program header table entry(%d)] p_memsz=%08x\n", i, pht->p_memsz);
		printf("[program header table entry(%d)] p_flags=%08x\n", i, pht->p_flags);
		printf("[program header table entry(%d)] p_align=%08x\n", i, pht->p_align);
		printf("\n");
*/
		table_base += hdr->e_phentsize;
	}
	
	table_base = hdr->e_shoff + base;
	for(i=0; i< hdr->e_shnum; i++){
		read_data(pid, table_base, sht, hdr->e_shentsize);
/*
		printf("[section header table entry(%d)] s_name=%08x\n", i, sht->s_name);
		printf("[section header table entry(%d)] s_type=%08x\n", i, sht->s_type);
		printf("[section header table entry(%d)] s_flags=%08x\n", i, sht->s_flags);
		printf("[section header table entry(%d)] s_addr=%08x\n", i, sht->s_addr);
		printf("[section header table entry(%d)] s_offset=%08x\n", i, sht->s_offset);
		printf("[section header table entry(%d)] s_size=%08x\n", i, sht->s_size);
		printf("[section header table entry(%d)] s_link=%08x\n", i, sht->s_link);
		printf("[section header table entry(%d)] s_info=%08x\n", i, sht->s_info);
		printf("[section header table entry(%d)] s_addralign=%08x\n", i, sht->s_addralign);
		printf("[section header table entry(%d)] s_entsize=%08x\n", i, sht->s_entsize);
		printf("\n");
*/
		if ((sht->s_type == 0x00000001) && (sht->s_flags == 0x00000006) && (sht->s_size > 0x00001000)){
			text_base = sht->s_offset + base;
			text_size = sht->s_size;
			free(hdr);
			free(pht);
			free(sht);
			return 0;
		}
		table_base += hdr->e_shentsize;
	}

	free(hdr);
	free(pht);
	free(sht);
	return 1;
}


struct link_map *locate_linkmap(int pid, void *base){
	Elf32_Ehdr      *ehdr   = malloc(sizeof(Elf32_Ehdr));
	Elf32_Phdr      *phdr   = malloc(sizeof(Elf32_Phdr));
	Elf32_Dyn       *dyn    = malloc(sizeof(Elf32_Dyn));
	Elf32_Word      got;
	struct link_map *l      = malloc(sizeof(struct link_map));
	unsigned long   phdr_addr , dyn_addr , map_addr;


	/* first we check from elf header, mapped at 0x08048000, the offset
	 * to the program header table from where we try to locate
	 * PT_DYNAMIC section.
	 */

	read_data(pid , base, ehdr , sizeof(Elf32_Ehdr));
	
	phdr_addr = base + ehdr->e_phoff;
	printf("[program header table address(start)]phdr_addr=%08x\n", phdr_addr);

	read_data(pid , phdr_addr, phdr, sizeof(Elf32_Phdr));
	
	while ( phdr->p_type != PT_DYNAMIC ) {
		//printf("read_data: pid=%d, addr=%08x, vptr=%08x, len=%d\n", pid, phdr_addr += sizeof(Elf32_Phdr), phdr, sizeof(Elf32_Phdr));
		read_data(pid, phdr_addr += sizeof(Elf32_Phdr), phdr, sizeof(Elf32_Phdr));
	}
	
	printf("[program header table entry table address]phdr_addr=%08x\n", phdr_addr);
	/* now go through dynamic section until we find address of the GOT
	 */
	printf("[program header table entry virtual address]phdr->p_vaddr=%08x\n", phdr->p_vaddr);//virtual address
	read_data(pid, phdr->p_vaddr, dyn, sizeof(Elf32_Dyn));
	dyn_addr = phdr->p_vaddr;
	printf("[program header table entry physical address]dyn_addr=%08x\n", dyn_addr);//dynamic address
	printf("DT_PLTGOT=%d\n", DT_PLTGOT);//table entry type

	while ( dyn->d_tag != DT_PLTGOT ) {
		printf("[section table entry address]dyn_addr=%08x (%08x)\n", dyn_addr, (dyn_addr-0x8df0));		
		read_data(pid, dyn_addr += sizeof(Elf32_Dyn), dyn, sizeof(Elf32_Dyn));
	}
	
	printf("[section table entry address]dyn_addr=%08x\n", dyn_addr);
	got = (Elf32_Word) dyn->d_un.d_ptr;
	got += 4; 		/* second GOT entry, remember? */

	printf("got=%08x\n", got);
	
	/* now just read first link_map item and return it */
	read_data(pid, (unsigned long) got, &map_addr , 4);
	printf("map_addr=%08x\n", map_addr);
	read_data(pid , map_addr, l , sizeof(struct link_map));
	printf("link_map=%08x\n", l);
	free(phdr);
	free(ehdr);
	free(dyn);

	return l;
}

/* search locations of DT_SYMTAB and DT_STRTAB and save them into global
 * variables, also save the nchains from hash table.
 */

void resolv_tables(int pid , struct link_map *map){
	Elf32_Dyn       *dyn    = malloc(sizeof(Elf32_Dyn));
	unsigned long   addr;

	addr = (unsigned long) map->l_ld;
	printf("addr=%08x\n", addr);

	read_data(pid , addr, dyn, sizeof(Elf32_Dyn));

	while ( dyn->d_tag ) {
		switch ( dyn->d_tag ) {

			case DT_HASH:
				read_data(pid,dyn->d_un.d_ptr +	map->l_addr+4, &nchains , sizeof(nchains));
				break;

			case DT_STRTAB:
				strtab = dyn->d_un.d_ptr;
				break;

			case DT_SYMTAB:
				symtab = dyn->d_un.d_ptr;
				break;

			default:
				break;
		}

		addr += sizeof(Elf32_Dyn);
		read_data(pid, addr , dyn , sizeof(Elf32_Dyn));
	}

	free(dyn);
}

/* find symbol in DT_SYMTAB */

unsigned long find_sym_in_tables(int pid, struct link_map *map , char *sym_name){
	
	Elf32_Sym       *sym = malloc(sizeof(Elf32_Sym));
	char            *str;
	int             i;

	i = 0;
	printf("nchains=%d\n", nchains);
	while (i < nchains) {
		read_data(pid, symtab+(i*sizeof(Elf32_Sym)), sym, sizeof(Elf32_Sym));
		i++;

		if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC) continue;

		/* read symbol name from the string table */
		str = read_str(pid, strtab + sym->st_name);
		printf("sym_name='%s', str='%s'\n", sym_name, str);
		if(strncmp(str , sym_name , strlen(sym_name)) == 0)
			return(map->l_addr+sym->st_value);
	}

	/* no symbol found, return 0 */
	return 0;
}


void *get_base(const char *lib_name, int pid){
	char buf[256];
	char *part;
	char *part2;
	int tmp;
	FILE *fp;
	tmp = sprintf(buf, "/proc/%d/maps", pid);
	buf[tmp+1] = '\0';
	
	fp = fopen(buf, "r");
	if (fp != NULL){
		char line[256];
		while (fgets(line, 255, fp) != NULL){
			//printf("%s", line);
			part = strstr(line, lib_name);
			if (part != NULL){
				//printf("part=%s\n", part);
				part2 = strtok(line, "-");
				if (part2 != NULL){
					sscanf(part2, "%x", &tmp);
					fclose(fp);
					return (void *)tmp;
				}
			}
			
		}
	}
	fclose(fp);
	//printf("[%d] %s \n", pid, lib_name);
	return 0x00008000;
}


void *get_size(const char *lib_name, int pid, void *base){
	char buf[256];
	char *part;
	char *part2;
	int tmp;
	FILE *fp;
	tmp = sprintf(buf, "/proc/%d/maps", pid);
	buf[tmp+1] = '\0';
	
	fp = fopen(buf, "r");
	if (fp != NULL){
		char line[256];
		while (fgets(line, 255, fp) != NULL){
			//printf("%s", line);
			part = strstr(line, lib_name);
			if (part != NULL){
				//printf("part=%s\n", part);
				part2 = strtok(line, " -");
				part2 = strtok(NULL, " -");
				if (part2 != NULL){
					sscanf(part2, "%x", &tmp);
					fclose(fp);
					return (void *)tmp - base;
				}
			}
			
		}
	}
	fclose(fp);
	//printf("[%d] %s \n", pid, lib_name);
	return 0;
}


void *get_function_by_symbol(const char *symbol, int pid, void * base){
	void *func_addr;
	struct link_map *map;
	printf("calling locate_linkmap\n");
	map = locate_linkmap(pid, base);
	printf("map=%p\n", map);
	printf("calling resolv_tables\n");
	resolv_tables(pid, map);
	printf("calling find_sym_in_tables\n");
	func_addr = find_sym_in_tables(pid, map, symbol);
	return func_addr;
}

void *get_function_by_pattern_lazy(const char *lib_name, int pid, const char * pattern){
	void *base;
	void *size;
	base = get_base(lib_name, pid);
	size = get_size(lib_name, pid, base);
	printf("base=%08x, size=%08x\n", base, size);


	int result;
	char* plaintext_out;
	base64_decodestate* state_in;

	plaintext_out = (char *)calloc((strlen(pattern)+1) *3, sizeof(char));

	printf("decodeing string '%s'\n", pattern);
	base64_init_decodestate(&state_in);
	result = base64_decode_block(pattern, strlen(pattern), plaintext_out, &state_in);
	//weird decode...
	printf("decoded %d bytes... ", result-2);
	int i;
	for(i=0; i<result-2; i++){
		printf(" %02x", plaintext_out[i]);
	}
	printf("\n");


	void *text_segment;
	text_segment = malloc(size);
	read_data(pid, base, text_segment, size);
	int idx = 0;
	for(i=0; i < size; i++){
		if (memcmp(text_segment+i, plaintext_out, result-2) == 0){
			idx = i;
			break;
		}
	}

	if (idx == 0) return 0;

	printf("function address=%08x, text segment base=%08x, idx=%d\n",base + idx, base, idx);
	free(plaintext_out);
	free(text_segment);

	return idx+base;
}



void *get_function_by_pattern(const char * pattern, int pid, void * base){
	int result;
	char* plaintext_out;
	base64_decodestate* state_in;

	plaintext_out = (char *)calloc((strlen(pattern)+1) *3, sizeof(char));

	printf("decodeing string '%s'\n", pattern);
	base64_init_decodestate(&state_in);
	result = base64_decode_block(pattern, strlen(pattern), plaintext_out, &state_in);
	//weird decode...
	printf("decoded %d bytes... ", result);
	int i;
	for(i=0; i<result-2; i++){
		printf(" %02x", plaintext_out[i]);
	}
	printf("\n");
	
	if(locate_text_segment(pid, base) > 0)return 0x00000000;

	printf("text_base=%08x, size=%d\n", text_base, text_size);
	
	void *text_segment;
	text_segment = malloc(text_size);
	read_data(pid, text_base, text_segment, text_size);
	int idx;
	for(i=0; i < text_size; i++){
		if (memcmp(text_segment+i, plaintext_out, result-2) == 0){
			idx = i;
			break;
		}
	}

	printf("function address=%08x, text segment base=%08x, idx=%d\n",text_base + idx, text_base, idx);
	free(plaintext_out);
	free(text_segment);

	return idx+text_base;
}
