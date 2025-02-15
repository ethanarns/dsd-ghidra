package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeString;

import java.util.List;

public class DsdSyncDataSymbol extends Structure {
    public UnsafeString name;
    public int address;
    public int kind;
    public int count;

    public DsdSyncDataSymbol() {
    }

    public DsdSyncDataSymbol(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("name", "address", "kind", "count");
    }

    public DsdSyncDataKind getKind() {
        return DsdSyncDataKind.VALUES[kind];
    }
}
