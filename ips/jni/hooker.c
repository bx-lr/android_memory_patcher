#include "hooker.h"

prologue hook_p[3];

char shellcode[] = "\x08\xd0\x4d\xe2\x50\x00\x8f\xe2\x40\x50\x9f\xe5\x35\xff\x2f\xe1"
"\x00\x30\xb0\xe3\x80\x10\xb0\xe3\x00\x40\xb0\xe1\x81\x11\xb0\xe1"
"\x00\x00\x8d\xe5\x04\x30\x8d\xe5\x05\x20\xb0\xe3\x01\x30\xb0\xe3"
"\x00\x00\xb0\xe3\x1c\x50\x9f\xe5\x35\xff\x2f\xe1\x70\x00\x20\xe1"
"\x04\x00\xb0\xe1\x08\x50\x9f\xe5\x35\xff\x2f\xe1\x08\xd0\x8d\xe2"
"\xb1\x32\xd1\xaf\x90\xdc\xd0\xaf\x65\x32\xd1\xaf\x2f\x64\x61\x74"
"\x61\x2f\x6c\x6f\x63\x61\x6c\x2f\x74\x6d\x70\x2f\x74\x65\x73\x74"
"\x2e\x6d\x61\x70\x00";
/*

"\x08\xd0\x4d\xe2\x50\x00\x8f\xe2\x40\x50\x9f\xe5\x35\xff\x2f\xe1"
"\x00\x30\xb0\xe3\x80\x10\xb0\xe3\x00\x40\xb0\xe1\x81\x11\xb0\xe1"
"\x00\x00\x8d\xe5\x04\x30\x8d\xe5\x05\x20\xb0\xe3\x01\x30\xb0\xe3"
"\x00\x00\xb0\xe3\x1c\x50\x9f\xe5\x35\xff\x2f\xe1\x04\x00\xb0\xe1"
"\x0c\x50\x9f\xe5\x35\xff\x2f\xe1\x08\xd0\x8d\xe2\x70\x00\x20\xe1"
"\xb1\x32\xd1\xaf\x90\xdc\xd0\xaf\x65\x32\xd1\xaf\x2f\x64\x61\x74"
"\x61\x2f\x6c\x6f\x63\x61\x6c\x2f\x74\x6d\x70\x2f\x74\x65\x73\x74"
"\x2e\x6d\x61\x70\x00";

"\x10\x40\x2d\xe9\x08\xd0\x4d\xe2\x50\x00\x8f\xe2\x40\x50\x9f\xe5"
"\x35\xff\x2f\xe1\x00\x30\xb0\xe3\x80\x10\xb0\xe3\x00\x40\xb0\xe1"
"\x81\x11\xb0\xe1\x00\x00\x8d\xe5\x04\x30\x8d\xe5\x05\x20\xb0\xe3"
"\x01\x30\xb0\xe3\x00\x00\xb0\xe3\x1c\x50\x9f\xe5\x35\xff\x2f\xe1"
"\x04\x00\xb0\xe1\x0c\x50\x9f\xe5\x35\xff\x2f\xe1\x08\xd0\x8d\xe2"
"\x10\x80\xbd\xe8\xb1\x32\xd1\xaf\x90\xdc\xd0\xaf\x65\x32\xd1\xaf"
"\x2f\x64\x61\x74\x61\x2f\x6c\x6f\x63\x61\x6c\x2f\x74\x6d\x70\x2f"
"\x74\x65\x73\x74\x2e\x6d\x61\x70\x00";
*/


void hook_init(){
	//libc setresgid
	hook_p[0] = (prologue) {1, 8, "\x90\x00\x2D\xE9\xD2\x70\xA0\xE3"};
	//libc printf
	hook_p[1] = (prologue) {0, 6, "\x0F\xB4\x0A\x4B\x07\xB5"};
	//libc _fork
	hook_p[2] = (prologue) {1, 8, "\x90\x00\x2D\xE9\x02\x70\xA0\xE3", 4, "\x04\xf0\x1f\xe5", 8, "\xff\x1f\x2d\xe9\x00\x40\x2d\xe9", 8, "\x00\x40\xbd\xe8\xff\x1f\xbd\xe8", 12, "\x00\xf0\x9f\xe5\xaa\xbb\xcc\xdd\xaa\xbb\xcc\xdd"};
	return;
}

int check_pattern(void *func_addr, int pid){
	int i;
	for (i=0; i<sizeof(hook_p)/sizeof(prologue); i++){
		void *tmp = malloc(hook_p[i].osz+1);
		read_data(pid, func_addr, tmp, hook_p[i].osz);
		if (memcmp(tmp, hook_p[i].overwrite, hook_p[i].osz) == 0){
			free(tmp);
			return i;			
		}
		free(tmp);
		
	}	
	return -1;
}


int inject_hook_code(void *func_addr, unsigned char *hook_decode, int len, int idx, int pid){
	//long ret;
	struct pt_regs regs, newregs;
	
	unsigned char *buf = (unsigned char *)malloc(sizeof(len));
	void *tmp_addr = 0x40000000;
	int i;

	while (1){
		LOOPSTART:
		tmp_addr += 1;
		if (read_data(pid, tmp_addr, buf, sizeof(shellcode)) < 0){
		 	tmp_addr += 1024;
		}
		for (i = 0; i < len; i++){
			if (buf[i] != '\0') goto LOOPSTART;
			if ((int)tmp_addr % 4 != 0) goto LOOPSTART;
		}
		break;
	}
	
	free(buf);
	printf("func_addr=%08x\n", func_addr);
	printf("tmp_addr=%08x\n", tmp_addr);
	write_data(pid, func_addr, hook_p[idx].hook, hook_p[idx].hsz);//write function hook 
	write_data(pid, func_addr + hook_p[idx].hsz, &tmp_addr, 4);//write hook location
	
	int total_size = hook_p[idx].savesz + len + hook_p[idx].restoresz + hook_p[idx].osz + hook_p[idx].retsz;
	buf = (unsigned char *)malloc(total_size);

	memcpy(buf, hook_p[idx].save, hook_p[idx].savesz);//push r0-12, lr
	printf("hook buffer: ");
	for (i=0; i < total_size; i++){
		printf("%02x ", buf[i]);
	}
	printf("\n");

	memcpy(buf+hook_p[idx].savesz, hook_decode, len-2);//hook
	printf("hook buffer: ");
	for (i=0; i < total_size; i++){
		printf("%02x ", buf[i]);
	}
	printf("\n");

	memcpy(buf+hook_p[idx].savesz+len, hook_p[idx].restore, hook_p[idx].restoresz);//pop r0-12, lr
	printf("hook buffer: ");
	for (i=0; i < total_size; i++){
		printf("%02x ", buf[i]);
	}
	printf("\n");
	
	memcpy(buf+hook_p[idx].savesz+len+hook_p[idx].restoresz, hook_p[idx].overwrite, hook_p[idx].osz);//overwritten bytes
	printf("hook buffer: ");
	for (i=0; i < total_size; i++){
		printf("%02x ", buf[i]);
	}
	printf("\n");


	memcpy(buf+hook_p[idx].savesz+len+hook_p[idx].restoresz+hook_p[idx].osz, hook_p[idx].ret, hook_p[idx].retsz); //ldr pc
	printf("hook buffer: ");
	for (i=0; i < total_size; i++){
		printf("%02x ", buf[i]);
	}
	printf("\n");

	write_data(pid, tmp_addr, buf, total_size);//write hook logic
	//write overwritten function prologue to tail of hook logic
	i = func_addr + hook_p[idx].hsz; //address to return to 
	write_data(pid, tmp_addr + total_size - 4, &i, 4);//write address to return to
	
/*
not working but this should be a shellcode loader....
	write_data(pid, tmp_addr, shellcode, sizeof(shellcode));
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) return -1;
	printf("\tr0=%08x\n", regs.ARM_r0);
	printf("\tsp=%08x\n", regs.ARM_sp);
	printf("\tlr=%08x\n", regs.ARM_lr);
	printf("\tpc=%08x\n", regs.ARM_pc);
	memcpy(&newregs, &regs, sizeof(struct pt_regs));
	newregs.ARM_pc = tmp_addr;
	if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs) == -1) return -1;
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) return -1;
	wait(NULL);
	if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs) == -1) return -1;
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) return -1;

*/
/*
	//ptrace_detach(pid);
int Tpid, stat, res;
int signo;
int ip, sp;
int ipoffs, spoffs;
unsigned int memcontents = 0, startcontents = 0, watchaddr = 0;



	printf("Attaching to process %d\n",pid);
	if ((ptrace(PTRACE_ATTACH, pid, 0, 0)) != 0) {;
		printf("Attach result %d\n",res);
	}
	res = waitpid(pid, &stat, WUNTRACED);
	if ((res != pid) || !(WIFSTOPPED(stat)) ) {
		printf("Unexpected wait result res %d stat %x\n",res,stat);
		exit(1);
	}
	printf("Wait result stat %x pid %d\n",stat, res);
	stat = 0;
	signo = 0;

	while (1) {
		printf("stepping...\n");
		if ((res = ptrace(PTRACE_SINGLESTEP, pid, 0, signo)) < 0) {
			perror("Ptrace singlestep error");
			exit(1);
		}

		res = wait(&stat);

		if ((signo = WSTOPSIG(stat)) == SIGTRAP) {
			signo = 0;
		}
		if ((signo == SIGHUP) || (signo == SIGINT)) {
			ptrace(PTRACE_CONT, Tpid, 0, signo);
			printf("Child took a SIGHUP or SIGINT. We are done\n");
			break;
		}
	}
	printf("Debugging complete\n");




	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) return -1;
	printf("[ptrace getregs]ret=%d\n", ret);
	printf("\tr0=%08x\n", regs.ARM_r0);
	printf("\tr1=%08x\n", regs.ARM_r1);
	printf("\tr2=%08x\n", regs.ARM_r2);		
	printf("\tr3=%08x\n", regs.ARM_r3);
	printf("\tr4=%08x\n", regs.ARM_r4);
	printf("\tr5=%08x\n", regs.ARM_r5);
	printf("\tr6=%08x\n", regs.ARM_r6);
	printf("\tr7=%08x\n", regs.ARM_r7);		
	printf("\tr8=%08x\n", regs.ARM_r8);
	printf("\tr9=%08x\n", regs.ARM_r9);
	printf("\tr10=%08x\n", regs.ARM_r10);
	printf("\tfp=%08x\n", regs.ARM_fp);
	printf("\tip=%08x\n", regs.ARM_ip);		
	printf("\tsp=%08x\n", regs.ARM_sp);
	printf("\tlr=%08x\n", regs.ARM_lr);
	printf("\tpc=%08x\n", regs.ARM_pc);
	printf("\tcpsr=%08x\n", regs.ARM_cpsr);
	
	memcpy(&newregs, &regs, sizeof(struct pt_regs));

	newregs.ARM_pc = 0xAFD0D6E0;//address of fork

	newregs.ARM_pc = 0xAFD0CFD1;//address of malloc()
	//newregs.ARM_pc = 0xAFD13A69;//address of sbrk()
	if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs) == -1) return -1;
	int i;
	for (i=0; i < 11; i++){
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) return -1;
		printf("wait(null) = %d\n", wait(NULL));
		if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs) == -1) return -1;
		printf("[ptrace getregs]step=%d\n", i);
		printf("\tr0=%08x\n", newregs.ARM_r0);
		printf("\tr1=%08x\n", newregs.ARM_r1);
		printf("\tr2=%08x\n", newregs.ARM_r2);		
		printf("\tr3=%08x\n", newregs.ARM_r3);
		printf("\tr4=%08x\n", newregs.ARM_r4);
		printf("\tr5=%08x\n", newregs.ARM_r5);
		printf("\tr6=%08x\n", newregs.ARM_r6);
		printf("\tr7=%08x\n", newregs.ARM_r7);		
		printf("\tr8=%08x\n", newregs.ARM_r8);
		printf("\tr9=%08x\n", newregs.ARM_r9);
		printf("\tr10=%08x\n", newregs.ARM_r10);
		printf("\tfp=%08x\n", newregs.ARM_fp);
		printf("\tip=%08x\n", newregs.ARM_ip);		
		printf("\tsp=%08x\n", newregs.ARM_sp);
		printf("\tlr=%08x\n", newregs.ARM_lr);
		printf("\tpc=%08x\n", newregs.ARM_pc);
		printf("\tcpsr=%08x\n", newregs.ARM_cpsr);
		ptrace(PTRACE_CONT, pid, 0, 0);
		printf("wait(null) = %d\n", wait(NULL));
	}

	ptrace(PTRACE_SETREGS, pid, NULL, &regs); //resume execution...
*/
	//write hook_decode to file
	//save registers
	//get address of mmap
	//call mmap in hooked process
	//restore registers
	//or...
	//call malloc(size of hook stuff)
	//call mprotect(malloc pointer)
	return 1;
}


int hook_it(void *func_addr, const char *function_hook, int pid){
	printf("func_addr=%08x, function_hook=%s\n", func_addr, function_hook);

	int len;
	unsigned char* hook_decode;
	base64_decodestate* state_in;

	hook_decode = (unsigned char *)calloc((strlen(function_hook)+1) *3, sizeof(char));

	//printf("decodeing string '%s'\n", function_hook);
	base64_init_decodestate(&state_in);
	len = base64_decode_block(function_hook, strlen(function_hook), hook_decode, &state_in);
	len = len-2;
	//weird decode...

	//printf("decoded %d bytes... ", len-2);
/*
	int i;
	for(i=0; i<len-2; i++){
		printf(" %02x", hook_decode[i]);
	}
	printf("\n");

	for (i=0; i<sizeof(hook_p)/sizeof(prologue); i++){
		printf("hook_p[%d].mode=%d, hook_p[%d].size=%d, hook_p[%d].pattern=", i, hook_p[i].mode, i, hook_p[i].size, i);
		int tmp;
		for (tmp=0; tmp < hook_p[i].size; tmp++){
			printf("%02x ", hook_p[i].pattern[tmp]);
		}
		printf("\n");
	}
*/
//check the func_addr to see if it matches any pattern in hook_p
	int idx = check_pattern(func_addr, pid);
	printf("check_pattern returned %d\n", idx);
	if (idx == -1){
		free(hook_decode);
		return 0;
	}
	
	if (inject_hook_code(func_addr, hook_decode, len, idx, pid) == -1){
		free(hook_decode);
		return 0;
	}
	
	free(hook_decode);
	return 1;
}
	
