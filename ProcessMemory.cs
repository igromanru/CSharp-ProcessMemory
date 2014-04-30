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
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        private IntPtr handleProcess;
        private string p;

        public ProcessMemory(String processName)
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
            return ReadProcessMemory(handleProcess, readAddress, readBuffer, readBuffer.Length, IntPtr.Zero);
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
            return WriteProcessMemory(handleProcess, writeAddress, writeBuffer, writeBuffer.Length, IntPtr.Zero);
        }

        public bool WriteMemoryInt(int writeAddress, int writeInt)
        {
            byte[] write = BitConverter.GetBytes(writeInt);
            return WriteMemory(writeAddress, write);
        }  

        // The pointer offets array have to looks like this: { 0xFB3E3C, 0x60, 0x8,...}
        // First offset makes the base address: 0x400000 + 0xFB3E3C = 0x13B3E3C
        public int ReadPointer(int startAddress, int[] offsets)
        {
            int pointedAddress = startAddress;
            for (int i = 0; i < offsets.Length; i++)
            {
                if (i == offsets.Length - 1)
                {
                    pointedAddress += offsets[i];
                }
                else if ((pointedAddress = ReadMemoryInt(pointedAddress + offsets[i])) == -1)
                {
                    pointedAddress = 0;
                    break;
                }
            }            
            return pointedAddress;
        }

        public void Close()
        {
            Process.LeaveDebugMode();
            if(handleProcess != null)
            {
                CloseHandle(handleProcess);
            }            
        }
    }
}
