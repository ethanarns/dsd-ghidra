package dsdghidra.sync;

import dsdghidra.dsd.SectionKind;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.util.exception.NotFoundException;

public class DsSection {
    private String name;
    private final DsModule module;
    private MemoryBlock memoryBlock;
    public final AddressSpace addressSpace;
    private int minAddress;
    private int maxAddress;

    public DsSection(String name, DsModule module, MemoryBlock memoryBlock) {
        this.name = name;
        this.module = module;
        this.memoryBlock = memoryBlock;
        this.addressSpace = memoryBlock.getAddressRange().getAddressSpace();
        this.minAddress = (int) memoryBlock.getStart().getOffset();
        this.maxAddress = (int) memoryBlock.getEnd().getOffset();
    }

    public String toString() {
        int start = (int) memoryBlock.getStart().getOffset();
        int end = (int) memoryBlock.getEnd().getOffset();
        return Integer.toHexString(start) + ".." + Integer.toHexString(end);
    }

    public Address getAddress(int offset) {
        if (offset < minAddress || offset > maxAddress) {
            return null;
        }
        return addressSpace.getAddress(offset);
    }

    public boolean contains(int address) {
        return address >= minAddress && address < maxAddress;
    }

    public DsSection split(Memory memory, int address)
    throws LockException, MemoryBlockException, NotFoundException {
        Address splitAddress = getAddress(address);

        memory.split(memoryBlock, splitAddress);
        maxAddress = address;

        String name = memoryBlock.getName() + ".split";
        MemoryBlock splitBlock = memory.getBlock(name);
        return new DsSection(name, module, splitBlock);
    }

    public void join(Memory memory, DsSection section)
    throws LockException, MemoryBlockException, NotFoundException {
        if (maxAddress + 1 != section.minAddress) {
            throw new MemoryBlockException("Sections are not contiguous");
        }

        MemoryBlock joinedBlock = memory.join(memoryBlock, section.memoryBlock);

        maxAddress = section.maxAddress;
        memoryBlock = joinedBlock;
    }

    public String getName() {
        return name;
    }

    public void setName(String name)
    throws LockException {
        this.name = name;
        this.memoryBlock.setName(module.name + name);
    }

    public MemoryBlock getMemoryBlock() {
        return memoryBlock;
    }

    public int getMinAddress() {
        return minAddress;
    }

    public int getMaxAddress() {
        return maxAddress;
    }

    public boolean matches(DsdSyncSection dsdSyncSection) {
        if (!name.equals(dsdSyncSection.base.name.getString())) {
            return false;
        }

        if (minAddress != dsdSyncSection.base.start_address) {
            return false;
        }
        if (maxAddress + 1 < dsdSyncSection.base.end_address) {
            // Max address is allowed to be greater than dsd's end_address because of alignment
            return false;
        }

        SectionKind sectionKind = dsdSyncSection.base.getKind();
        if (memoryBlock.isWrite() != sectionKind.isWriteable()) {
            return false;
        }
        if (memoryBlock.isExecute() != sectionKind.isExecutable()) {
            return false;
        }

        return true;
    }

    public void setRwxFlags(SectionKind kind) {
        memoryBlock.setWrite(kind.isWriteable());
        memoryBlock.setExecute(kind.isExecutable());
    }

    public void resetRwxFlags() {
        memoryBlock.setWrite(true);
        if (memoryBlock.isInitialized()) {
            memoryBlock.setExecute(true);
        }
    }
}
