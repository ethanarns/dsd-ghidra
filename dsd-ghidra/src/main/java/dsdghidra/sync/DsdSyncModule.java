package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;

import java.util.List;

public class DsdSyncModule extends Structure {
    public int base_address;
    public UnsafeList<DsdSyncSection> sections;
    public UnsafeList<DsdSyncDelinkFile> files;

    public DsdSyncModule() {
        super();
    }

    public DsdSyncModule(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("base_address", "sections", "files");
    }

    public DsdSyncSection[] getSections() {
        return sections.getArray(new DsdSyncSection[0], DsdSyncSection::new);
    }

    public DsdSyncDelinkFile[] getFiles() {
        return files.getArray(new DsdSyncDelinkFile[0], DsdSyncDelinkFile::new);
    }
}
