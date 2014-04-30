using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace IgroGadgets
{
    public class ProcessMemory
    {
        enum ProcessAccessType
        {
            PROCESS_ALL_ACCESS = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION |
                                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME |
                                PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        } 

        [DllImport("kernel32.dll", SetLastError = true)]
        private extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private extern bool ReadProcessMemory(IntPtr hProcess, int lpBaseAddress, ref byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private extern bool WriteProcessMemory(IntPtr hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private extern bool CloseHandle(IntPtr handle);

        private IntPtr handleProcess;

        ProcessMemory(String processName)
        {
            Process.EnterDebugMode();
            OpenProcessByName(processName);
        }

        public IntPtr OpenProcessByName(String processName)
        {
            Process process = Process.GetProcessesByName(processName)[0];
            handleProcess = OpenProcess((int)ProcessAccessType.PROCESS_ALL_ACCESS, false, process.Id);
            return handleProcess;
        }

        public bool ReadMemory(int readAddress, ref byte[] readBuffer)
        {
            int bytesRead;
            return ReadProcessMemory(handleProcess, readAddress, ref readBuffer, readBuffer.Length, out bytesRead);
        }

        public int ReadMemoryInt(int readAddress)
        {
            int readInt = -1;
            byte[] readBuffer = new byte[sizeof(int)];
            if (ReadMemory(readAddress, ref readBuffer))
            {
                readInt = BitConverter.ToInt32(readBuffer, 0);
            }
            return readInt;
        }

        public bool WriteMemory(int writeAddress, byte[] writeBuffer)
        {
            int bytesWritten;
            return WriteProcessMemory(handleProcess, writeAddress, writeBuffer, writeBuffer.Length, out bytesWritten);
        }

        public bool WriteMemoryInt(int writeAddress, int writeInt)
        {
            byte[] write = BitConverter.GetBytes(writeInt);
            return WriteMemory(writeAddress, write);
        }  

        // The pointer offets array have to looks like this: { 0xFB3E3C, 0x60, 0x8,...}
        // First offset makes the base address: 0x400000 + 0xFB3E3C = 0x13B3E3C
        public int ReadPointer(int startAddress, int[] pointerOffsets)
        {
            int pointedAddress = startAddress;
            foreach(int offset in pointerOffsets)
            {
                if ((pointedAddress = ReadMemoryInt(pointedAddress + offset)) == -1)
                {
                    pointedAddress = 0;
                    break;
                }
            }            
            return pointedAddress;
        }

        public void Close()
        {
            if(handleProcess != null)
            {
                CloseHandle(handleProcess);
            }            
        }
    }
}
