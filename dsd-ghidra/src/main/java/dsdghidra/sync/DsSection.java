package dsdghidra.sync;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

public class DsSection {
    public final String name;
    public final MemoryBlock memoryBlock;
    public final AddressSpace addressSpace;
    public final int minAddress;
    public final int maxAddress;

    public DsSection(String name, MemoryBlock memoryBlock) {
        this.name = name;
        this.memoryBlock = memoryBlock;
        this.addressSpace = memoryBlock.getAddressRange().getAddressSpace();
        this.minAddress = (int) this.addressSpace.getMinAddress().getOffset();
        this.maxAddress = (int) this.addressSpace.getMaxAddress().getOffset();
    }

    public String toString() {
        int start = (int) memoryBlock.getStart().getOffset();
        int end = (int) memoryBlock.getEnd().getOffset();
        return Integer.toHexString(start) + ".." + Integer.toHexString(end);
    }

    public Address getAddress(int offset) {
        if (offset < minAddress || offset >= maxAddress) {
            return null;
        }
        return addressSpace.getAddress(offset);
    }

    public boolean contains(int address) {
        return address >= minAddress && address < maxAddress;
    }
}
