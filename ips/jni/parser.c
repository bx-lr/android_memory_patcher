
#include "parser.h"

/*
TODO: (parser)use inih to parse a config file which will tell us
	char * process_name		;name of the process to inject into (/proc/PID/cmdline)
	int    injected			;1 = we injected
	int    pid			;process id of the process to inject into (if null process not running)
	char * image_name		;image name of the so to lookup (from /proc/PID/maps ?)
	char * function_symbol		;symbol to hook (may be null, check procedure linkage table)
	char * function_pattern		;if no symbol walk the .text segment reading bytes and do a compare (base64 from config)
	char * function_hook 		;base64 encoded data from config that is the function specific hook

TODO: (parser)load the config file and create a struct for each entry in the config
*/


static int handler(void* user, const char* section, const char* name, const char* value)
{
    configuration* pconfig = (configuration*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("process", "name")) {
        pconfig->process_name = strdup(value);
    } else if (MATCH("process", "injected")) {
        pconfig->injected = atoi(value);
    } else if (MATCH("process", "pid")) {
        pconfig->pid = atoi(value);
    } else if (MATCH("process", "image")) {
        pconfig->image_name = strdup(value);
    } else if (MATCH("process", "symbol")) {
        pconfig->function_symbol = strdup(value);
    } else if (MATCH("process", "pattern")) {
        pconfig->function_pattern = strdup(value);
    } else if (MATCH("process", "hook")) {
        pconfig->function_hook = strdup(value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


int parse_file(configuration *config)
{

	if (ini_parse("test.ini", handler, config) < 0) {
		printf("Can't load 'test.ini'\n");
		return -1;
	}
	return 0;
}
