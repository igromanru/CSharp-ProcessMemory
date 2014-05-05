using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IgroGadgets
{
    public class AddressEntity<T>
    {
        public IntPtr Address { get; set; }
        public int[] Offsets { get; set; }
        public T Value { get; set; }

        public AddressEntity(int[] offsets)
        {
            Offsets = offsets;
        }

        public AddressEntity(IntPtr address)
        {
            Address = address;
            Offsets = new int[0];
        }

        public AddressEntity(IntPtr address, int[] offsets)
        {
            Address = address;
            Offsets = offsets;
        }

        public AddressEntity(int address, int[] offsets)
            : this(new IntPtr(address), offsets)
        {
        }
    }
}
