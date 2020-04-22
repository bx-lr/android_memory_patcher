#include <stdio.h>
#include <stdlib.h>
#include "parser.h"
#include "myptrace.h"
#include "resolve.h"
#include "hooker.h"


/*

TODO: (parser)load the config file and create a struct for each entry in the config
TODO: (process poller)implement process lookup by cmdline (search /proc) and populate the correct struct
TODO: (hookeng)implement hooking wrappers for the different types of function prolog's 
TODO: (main loop) for each struct, if not injected
	TODO: (ptrace)use ptrace to attach to the process
	TODO: (elfparser)resolve the function we are interested in by either symbol or binary pattern
	TODO: (hookeng)check the hook engine to see if we have a patch for the prolog and if so
	TODO: (ptrace)use ptrace to allocate a page of memory in the process
	TODO: (ptrace)use ptrace to write the hook function to the page of memory
	TODO: (ptrace)use ptrace, elfparser, and hookeng to patch the hook function so that it returns to the correct function
	TODO: (ptrace)use ptrace, elfparser, and hookeng to patch the function to redirect to our hook function
	TODO: (ptrace)resume process
TODO: goto process poller

TODO: implement multi process name hooking

*/






int main(int argc, char **argv)
{
	hook_init();
	
	configuration config;
	
	if (parse_file(&config) < 0){
		printf("Could not load config... exiting\n");
		return 1;
	}
	
	//pass config into process poller to get info
	while (1){

		if (poll_for_process(&config) < 0){
			printf("no new processes found\n");
			sleep(1);
			continue;
		}

		printf("Config loaded from 'test.ini': \n\tprocess_name=%s\n\tinjected=%d\n\tpid=%d", config.process_name, config.injected, config.pid);
		printf("\n\timage_name=%s\n\tfunction_symbol=%s\n\tfunction_pattern=%s\n\tfunction_hook=%s\n", config.image_name, config.function_symbol, config.function_pattern, config.function_hook);
	
		//long ret;
		//struct pt_regs data;
		//open /proc/pid/maps and get address range for config.image_name
			//if we do not get an address range set pid to 0 and continue
		//if we have a symbol
			//do symbol resolution to get function address
		//if we dont have a symbol but we have a pattern from config.function_pattern
			//do symbol resolution using ptrace to look for the pattern in the address range
		//if we dont have a function address set pid to 0 an continue
		//read some memory from the function address and send it to the hook engine
		//if the hook engine can not hook it set the pid to 0 and continue
		//since the hook engine can hook it... allocate memory in the process (think mmap of tmpfile)
		//write the hook engine fix and our patch function to the allocated memory 
		//write a jump at the function address to our hook 
		
		void *base;
		base = get_base(config.image_name, config.pid);
		printf("base=%08x\n", base);
		if (base == NULL){
			printf("unable to get lib base... restarting loop\n");
			config.pid = NULL;
			continue;
		}
		ptrace_attach(config.pid);

/*
		unsigned char buf[512];
		memset(buf, 0, sizeof(buf));
		read_data(config.pid, (long unsigned int)0x0000b120, &buf, 512);

		int i;
		i = 0;
		while (i <= 512){
			printf("buf[%d] %02x%02x%02x%02x\n", i, buf[i], buf[i+1], buf[i+2], buf[i+3]);
			i += 4;
		}

*/


		void *func_addr = NULL;
		if (config.function_symbol != NULL){
			printf("doing symbol lookup...\n");
			//func_addr = get_function_by_symbol(config.function_symbol, config.pid, base);
		}

		if (func_addr == NULL) {
			printf("symbol lookup failed\n");
			if (config.function_pattern != NULL) {
				printf("doing pattern lookup\n");
				func_addr = get_function_by_pattern(config.function_pattern, config.pid, base);
			}
		}


		if (func_addr == NULL) {
			printf("symbol lookup failed\n");
			if (config.function_pattern != NULL) {
				printf("doing pattern lookup(lazy)\n");
				func_addr = get_function_by_pattern_lazy(config.image_name, config.pid, config.function_pattern);
			}
		}
		
		if (func_addr == NULL){
			printf("pattern and symbol lookup failed... restarting loop\n");
			ptrace_detach(config.pid);
			config.pid = NULL;
			sleep(3);
			continue;
		}
		
		printf("function address resolved to=%08x\n", func_addr);
		
		if (hook_it(func_addr, config.function_hook, config.pid) == 0){
			printf("function hooking failed... restarting loop\n");
			ptrace_detach(config.pid);
			config.pid = NULL;
			sleep(3);
			continue;
		}
		printf("function hooked!!!!!\n");
		ptrace_detach(config.pid);
		config.injected = 1;
		sleep(3);

//ptrace test stuff...
/*
		ret = ptrace(PTRACE_ATTACH, config.pid, NULL, NULL);
		printf("[ptrace attach]ret=%d\n", ret);

		waitpid(config.pid, NULL, 0);

		ret = ptrace(PTRACE_GETREGS, config.pid, &data, &data);
		printf("[ptrace getregs]ret=%d\n", ret);
		printf("\tr0=%08x\n", data.ARM_r0);
		printf("\tr1=%08x\n", data.ARM_r1);
		printf("\tr2=%08x\n", data.ARM_r2);		
		printf("\tr3=%08x\n", data.ARM_r3);
		printf("\tr4=%08x\n", data.ARM_r4);
		printf("\tr5=%08x\n", data.ARM_r5);
		printf("\tr6=%08x\n", data.ARM_r6);
		printf("\tr7=%08x\n", data.ARM_r7);		
		printf("\tr8=%08x\n", data.ARM_r8);
		printf("\tr9=%08x\n", data.ARM_r9);
		printf("\tr10=%08x\n", data.ARM_r10);
		printf("\tfp=%08x\n", data.ARM_fp);
		printf("\tip=%08x\n", data.ARM_ip);		
		printf("\tsp=%08x\n", data.ARM_sp);
		printf("\tlr=%08x\n", data.ARM_lr);
		printf("\tpc=%08x\n", data.ARM_pc);

		//ret = ptrace(PTRACE_CONT, config.pid, NULL, NULL);
		//printf("[ptrace cont]ret=%d\n", ret);

		ptrace(PTRACE_DETACH, config.pid, NULL, NULL);
*/
//end ptrace test stuff....	
		sleep(5);

	}			


	
	
	return 0;
}

