package dsdghidra.sync;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

public class DsAddressSpace {
    public MemoryBlock memoryBlock;
    public AddressSpace addressSpace;
    public int minValue;
    public int maxValue;

    public DsAddressSpace(MemoryBlock memoryBlock) {
        this.memoryBlock = memoryBlock;
        AddressRange addressRange = memoryBlock.getAddressRange();
        this.addressSpace = addressRange.getAddressSpace();
        this.minValue = (int) addressRange.getMinAddress().getOffset();
        this.maxValue = (int) addressRange.getMaxAddress().getOffset();
    }

    public Address fromAbsolute(int absoluteAddress) {
        if (absoluteAddress < minValue || absoluteAddress >= maxValue) {
            return null;
        }
        return addressSpace.getAddress(absoluteAddress);
    }

    public boolean contains(int address) {
        return address >= minValue && address < maxValue;
    }
}
