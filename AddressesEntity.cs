using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IgroGadgets
{
    public class AddressesEntity<T>
    {
        public IntPtr Address { get; set; }
        public int[] Offsets { get; set; }
        public T Value { get; set; }

        public AddressesEntity(IntPtr address, int[] offsets)
        {
            Address = address;
            Offsets = offsets;
        }

        public AddressesEntity(int address, int[] offsets)
            : this(new IntPtr(address), offsets)
        {
        }
    }
}
