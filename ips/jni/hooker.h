#include "include/libb64-1.2/include/b64/cdecode.h"
#include "myptrace.h"

typedef struct prologue {
	int mode;			// arm/thumb mode (unused)
	int osz;			// size of pattern 
	unsigned char *overwrite;	// prologue pattern (overwritten bytes)
	int hsz;			// size of function hook code
	unsigned char *hook;		// function hook code
	int savesz;			
	unsigned char *save;		//save registers
	int restoresz;
	unsigned char *restore;		//restore registers
	int retsz;
	unsigned char *ret;		//return to function
	
} prologue;

void hook_init();
int hook_it(void *func_addr, const char *function_hook, int pid);
