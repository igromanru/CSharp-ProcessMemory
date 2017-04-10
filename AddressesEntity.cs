using System;

namespace IgroGadgets.Memory
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
    }
}
