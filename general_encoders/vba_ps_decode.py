#!/usr/bin/env python3
import sys

''' Usage:
    ./vba_ps_decode.py <encoded_string>
    Example:
    ./vba_ps_decode.py "135121126125119125132131074"
    winmgmts:
'''

rot = 16
rev = sys.argv[1]
print(''.join([chr(int(rev[i:i+3])-rot) for i in range(0, len(rev), 3)]))
