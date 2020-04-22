#include "myptrace.h"


/* attach to pid */

void ptrace_attach(int pid) {
	if((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
		perror("ptrace_attach");
		exit(-1);
	}
	waitpid(pid , NULL , WUNTRACED);
}


/* continue execution */

void ptrace_cont(int pid) {
	int s;
	if((ptrace(PTRACE_CONT , pid , NULL , NULL)) < 0) {
		perror("ptrace_cont");
		exit(-1);
	}
	while (!WIFSTOPPED(s)) waitpid(pid , &s , WNOHANG);
}


/* detach process */

void ptrace_detach(int pid) {
	if(ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) {
		perror("ptrace_detach");
		exit(-1);
	}
}

/* read data from location addr */

int read_data(int pid, unsigned long addr, void *vptr, int len){
	//printf("read_data: pid=%d, addr=%08x, len=%d\n", pid, addr, len);
	int i , count;
	long word;
	unsigned long *ptr = (unsigned long *) vptr;
	count = i = 0;
	while (count < len) {
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr+count, NULL)) == -1) return -1;
		count += 4;
		ptr[i++] = word;
	}
	return 0;
}

char * read_str(int pid, unsigned long addr){
	char *ret = calloc(32, sizeof(char));
	read_data(pid, addr, ret, 32);
	return ret;
}



/* write data to location addr */	

void write_data(int pid, unsigned long addr, void *vptr, int len){
        int i , count;
       	long word;
	i = count = 0;
	while (count < len) {
		memcpy(&word , vptr+count , sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid , addr+count , word);
		count +=4;
	}
}
