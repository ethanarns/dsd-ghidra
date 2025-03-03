package dsdghidra.dsd;

public enum SectionKind {
    Code,
    Data,
    Rodata,
    Bss;

    public static final SectionKind[] VALUES = SectionKind.values();

    public boolean isBss() {
        return this == SectionKind.Bss;
    }

    public boolean isWriteable() {
        return this != SectionKind.Code && this != SectionKind.Rodata;
    }

    public boolean isExecutable() {
        return this == SectionKind.Code;
    }
}
