#include "poll.h"

int get_process_id(const char *process_name ){
	DIR *dp;
	FILE *fp;
	struct dirent *ep;
	char buf[128];
	char commandline[128];
	char *part;
	dp = opendir("/proc/");
	if (dp != NULL){
		while (ep = readdir(dp)){
			sprintf(buf, "/proc/%s/cmdline", ep->d_name);
			int tmp = strlen(buf);
			buf[tmp+1] = '\0';
			if((fp = fopen(buf, "r")) != NULL){
				fread(commandline, 1, 120,fp);
				fclose(fp);
				tmp = strlen(commandline);
				commandline[tmp+1] = '\0';
				//printf("commandline(%d)=%s, process_name(%d)=%s\n", strlen(commandline), commandline, strlen(process_name), process_name);
				part = strtok(commandline, "/");
				while (part != NULL){
					if (strncmp(part, process_name, strlen(process_name)) == 0){
						return atoi(ep->d_name);
					}
					part = strtok(NULL, "/");
				}
			}
			
		}
		closedir(dp);
	}
	
	return -1;
}


int poll_for_process(configuration *config){
	//printf("[poll] process_name=%s\n", config->process_name);
	pid_t pid;
	pid = get_process_id(config->process_name);
	if (pid > -1){
		//printf("[poll] pid=%d\n", pid);
		if(config->pid == pid){
			printf("pids match\n");
			return -1;
		}
		config->pid = pid;
		return 0;
	}
	config->pid = 0;
	return -1;
	
}
