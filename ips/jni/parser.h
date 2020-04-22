
#include "include/inih_r22/ini.h"

typedef struct configuration
{
	const char* process_name;		//name of the process to inject into (/proc/PID/cmdline)
	int    injected;				//1 = we injected
	int    pid;				//process id of the process to inject into (if null process not running)
	const char* image_name;			//image name of the so to lookup (from /proc/PID/maps ?)
	const char* function_symbol;			//symbol to hook (may be null, check procedure linkage table)
	const char* function_pattern;			//if no symbol walk the .text segment reading bytes and do a compare (base64 from config)
	const char* function_hook ;			//base64 encoded data from config that is the function specific hook
} configuration;

int parse_file(configuration *);
