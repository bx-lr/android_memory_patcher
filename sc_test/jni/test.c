#include <stdio.h>
#include <stdlib.h>


char sc[] = "\x10\x40\x2d\xe9\x08\xd0\x4d\xe2\x50\x00\x8f\xe2\x40\x50\x9f\xe5"
"\x35\xff\x2f\xe1\x00\x30\xb0\xe3\x80\x10\xb0\xe3\x00\x40\xb0\xe1"
"\x81\x11\xb0\xe1\x00\x00\x8d\xe5\x04\x30\x8d\xe5\x05\x20\xb0\xe3"
"\x01\x30\xb0\xe3\x00\x00\xb0\xe3\x1c\x50\x9f\xe5\x35\xff\x2f\xe1"
"\x04\x00\xb0\xe1\x0c\x50\x9f\xe5\x35\xff\x2f\xe1\x08\xd0\x8d\xe2"
"\x10\x80\xbd\xe8\xb1\x32\xd1\xaf\x90\xdc\xd0\xaf\x65\x32\xd1\xaf"
"\x2f\x64\x61\x74\x61\x2f\x6c\x6f\x63\x61\x6c\x2f\x74\x6d\x70\x2f"
"\x74\x65\x73\x74\x2e\x6d\x61\x70\x00\x00";

int main(int argc, char **argv)
{
	int a = 0;
	int (*func)();
	func = (int (*)()) sc;
	(int)(*func)();
	while (1){
	if(a > 999)break; 
	sleep(1);
	a += 1;
	}
	(int)(*func)();
	return 0;
}

