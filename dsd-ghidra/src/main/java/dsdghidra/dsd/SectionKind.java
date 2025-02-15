package dsdghidra.dsd;

import ghidra.program.model.symbol.RefType;

public enum SectionKind {
    Code,
    Data,
    Bss;

    public static final SectionKind[] VALUES = SectionKind.values();

    public boolean isBss() {
        return this == SectionKind.Bss;
    }
}
