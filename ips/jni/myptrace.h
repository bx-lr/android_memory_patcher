#include <sys/ptrace.h>
#include <sys/wait.h>

#define	SIGHUP	1
#define	SIGINT	2
#define	SIGTRAP	5

void ptrace_attach(int pid);
void ptrace_cont(int pid);
void ptrace_detach(int pid);
int read_data(int pid, unsigned long addr ,void *vptr, int len);
char * read_string(int pid, unsigned long addr);
void write_data(int pid, unsigned long addr ,void *vptr, int len);
