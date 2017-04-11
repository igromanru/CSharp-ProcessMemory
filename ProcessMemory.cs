using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace IgroGadgets.Memory
{
    public class ProcessMemory : IDisposable
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
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out()] byte[] lpBuffer, UIntPtr dwSize, UIntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr dwSize, UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        public static bool Is64Bit => IntPtr.Size == 8;

        private IntPtr _handleProcess;
        
        public ProcessMemory(string processName)
        {
            try
            {
                Process.EnterDebugMode();
            }
            catch (Exception)
            {
                throw new NoAdminPrivilegesException();
            }
            OpenProcessByName(processName);
        }

        ~ProcessMemory()
        {
            Dispose();
        }

        private void OpenProcessByName(string processName)
        {
            try
            {
                Process[] processes = Process.GetProcessesByName(processName);
                _handleProcess = OpenProcess((int)ProcessAccessType.PROCESS_ALL_ACCESS, false, processes[0].Id);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw new NoProcessFoundException();
            }
        }

        public bool ReadMemory(IntPtr readAddress, ref byte[] readBuffer)
        {
            return ReadProcessMemory(_handleProcess, readAddress, readBuffer, (UIntPtr)readBuffer.Length, UIntPtr.Zero);
        }

        public bool ReadMemoryByte(IntPtr address, out byte value)
        {
            value = 0;
            var readBuffer = new byte[sizeof(byte)];
            var success = ReadProcessMemory(_handleProcess, address, readBuffer, (UIntPtr)1, UIntPtr.Zero);
            if (success)
            {
                value = readBuffer[0];
            }
            return success;
        }

        public bool ReadMemoryInt(IntPtr address, out int value)
        {
            value = 0;
            var readBuffer = new byte[sizeof(int)];
            var success = ReadMemory(address, ref readBuffer);
            if (success)
            {
                value = BitConverter.ToInt32(readBuffer, 0);
            }
            return success;
        }

        public bool ReadMemoryLong(IntPtr address, out long value)
        {
            value = 0;
            var readBuffer = new byte[sizeof(long)];
            var success = ReadMemory(address, ref readBuffer);
            if (success)
            {
                value = BitConverter.ToInt64(readBuffer, 0);
            }
            return success;
        }

        public bool ReadMemoryFloat(IntPtr address, out float value)
        {
            value = 0;
            var readBuffer = new byte[sizeof(float)];
            var success = ReadMemory(address, ref readBuffer);
            if (success)
            {
                value = BitConverter.ToSingle(readBuffer, 0);
            }
            return success;
        }

        public bool ReadMemoryIntPr(IntPtr address, out IntPtr value)
        {
            long longValue = 0;
            int intValue = 0;
            var result = Is64Bit ? ReadMemoryLong(address, out longValue) : ReadMemoryInt(address, out intValue);
            value = IntPtr.Zero;
            if (result)
            {
                value = new IntPtr(Is64Bit ? longValue : intValue);
            }
            return result;
        }

        public bool WriteMemory(IntPtr writeAddress, byte[] writeBuffer)
        {
            return WriteProcessMemory(_handleProcess, writeAddress, writeBuffer, (UIntPtr)writeBuffer.Length, UIntPtr.Zero);
        }

        public bool WriteMemoryByte(IntPtr address, byte value)
        {
            return WriteProcessMemory(_handleProcess, address, BitConverter.GetBytes(value), (UIntPtr)1, UIntPtr.Zero);
        }

        public bool WriteMemoryInt(IntPtr address, int value)
        {
            return WriteMemory(address, BitConverter.GetBytes(value));
        }

        public bool WriteMemoryLong(IntPtr address, long value)
        {
            return WriteMemory(address, BitConverter.GetBytes(value));
        }

        public bool WriteMemoryFloat(IntPtr address, float value)
        {
            return WriteMemory(address, BitConverter.GetBytes(value));
        }

        /// <summary>
        /// Reading the address from a pointer
        /// </summary>
        /// <param name="address">base address</param>
        /// <param name="offsets">offsest array</param>
        /// <param name="resultAddress">>The address that is pointed to by the pointer.</param>
        /// <returns>True, if reading was successful</returns>
        public bool ReadPointer(int address, int[] offsets, out IntPtr resultAddress)
        {
            return ReadPointer(new IntPtr(address), offsets, out resultAddress);
        }

        /// <summary>
        /// Reading the address from a pointer
        /// </summary>
        /// <param name="address">base address</param>
        /// <param name="offsets">offsest array</param>
        /// <param name="resultAddress">>The address that is pointed to by the pointer.</param>
        /// <returns>True, if reading was successful</returns>
        public bool ReadPointer(long address, int[] offsets, out IntPtr resultAddress)
        {
            return ReadPointer(new IntPtr(address), offsets, out resultAddress);
        }

        /// <summary>
        /// Reading the address from a pointer
        /// </summary>
        /// <param name="address">base address</param>
        /// <param name="offsets">offsest array</param>
        /// <param name="resultAddress">>The address that is pointed to by the pointer.</param>
        /// <returns>True, if reading was successful</returns>
        public bool ReadPointer(IntPtr address, int[] offsets, out IntPtr resultAddress)
        {
            var result = true;
            resultAddress = IntPtr.Zero;
            if (ReadMemoryIntPr(address, out resultAddress))
            {
                for (var i = 0; i < offsets.Length; i++)
                {
                    if (i < offsets.Length - 1)
                    {
                        if (ReadMemoryIntPr(IntPtr.Add(resultAddress, offsets[i]), out resultAddress))
                        {
                            result = false;
                            break;
                        }
                    }
                    else
                    {
                        resultAddress = IntPtr.Add(resultAddress, offsets[i]);
                    }
                }
            }
            return result;
        }


        public void Dispose()
        {
            Process.LeaveDebugMode();
            if (!_handleProcess.Equals(IntPtr.Zero))
            {
                CloseHandle(_handleProcess);
            }
            GC.SuppressFinalize(this);
        }
    }
}
