#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>
#include "include/linker/link.h"
#include "include/libb64-1.2/include/b64/cdecode.h"

typedef struct my_elf_hdr
{
	unsigned char e_ident[15];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_startadr;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shtrndx;
	
}my_elf_hdr;

typedef struct my_pht_entry
{
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;

}my_pht_entry;

typedef struct my_sht_entry
{
	uint32_t s_name;
	uint32_t s_type;
	uint32_t s_flags;
	uint32_t s_addr;
	uint32_t s_offset;
	uint32_t s_size;
	uint32_t s_link;
	uint32_t s_info;
	uint32_t s_addralign;
	uint32_t s_entsize;

}my_sht_entry;


void * get_base(const char *lib_name, int pid);
void * get_function_by_symbol(const char * symbol, int pid, void * base);
void * get_function_by_pattern(const char * pattern, int pid, void * base);
void * get_function_by_pattern_lazy(const char *lib_name, int pid, const char * pattern);


