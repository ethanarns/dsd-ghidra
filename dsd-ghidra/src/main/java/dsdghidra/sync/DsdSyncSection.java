package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.dsd.SectionKind;
import dsdghidra.types.UnsafeString;

import java.util.List;

public class DsdSyncSection extends Structure {
    public UnsafeString name;
    public int start_address;
    public int end_address;
    public byte kind;

    public DsdSyncSection() {
        super();
    }

    public DsdSyncSection(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("name", "start_address", "end_address", "kind");
    }

    public SectionKind getKind() {
        return SectionKind.VALUES[kind];
    }
}
