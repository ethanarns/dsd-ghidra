package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import dsdghidra.types.UnsafeString;

import java.util.List;

public class DsdSyncDelinkFile extends Structure {
    public UnsafeString name;
    public UnsafeList<DsdSyncSection> sections;

    public DsdSyncDelinkFile() {
    }

    public DsdSyncDelinkFile(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("name", "sections");
    }

    public DsdSyncSection[] getSections() {
        return sections.getArray(new DsdSyncSection[0], DsdSyncSection::new);
    }
}
