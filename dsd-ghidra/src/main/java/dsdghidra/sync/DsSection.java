package dsdghidra.sync;

import ghidra.program.model.mem.MemoryBlock;

public class DsSection {
    public final String name;
    public final MemoryBlock memoryBlock;

    public DsSection(String name, MemoryBlock memoryBlock) {
        this.name = name;
        this.memoryBlock = memoryBlock;
    }

    public String toString() {
        int start = (int) memoryBlock.getStart().getOffset();
        int end = (int) memoryBlock.getEnd().getOffset();
        return Integer.toHexString(start) + ".." + Integer.toHexString(end);
    }
}
