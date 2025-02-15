package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;

import java.util.List;

public class DsdSyncModule extends Structure {
    public int base_address;
    public UnsafeList<DsdSyncSection> sections;
    public UnsafeList<DsdSyncDelinkFile> files;
    public UnsafeList<DsdSyncFunction> functions;
    public UnsafeList<DsdSyncDataSymbol> data_symbols;
    public UnsafeList<DsdSyncDataSymbol> bss_symbols;
    public UnsafeList<DsdSyncRelocation> relocations;

    public DsdSyncModule() {
        super();
    }

    public DsdSyncModule(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("base_address", "sections", "files", "functions", "data_symbols", "bss_symbols", "relocations");
    }

    public DsdSyncSection[] getSections() {
        return sections.getArray(new DsdSyncSection[0], DsdSyncSection::new);
    }

    public DsdSyncDelinkFile[] getFiles() {
        return files.getArray(new DsdSyncDelinkFile[0], DsdSyncDelinkFile::new);
    }

    public DsdSyncFunction[] getFunctions() {
        return functions.getArray(new DsdSyncFunction[0], DsdSyncFunction::new);
    }

    public DsdSyncDataSymbol[] getDataSymbols() {
        return data_symbols.getArray(new DsdSyncDataSymbol[0], DsdSyncDataSymbol::new);
    }

    public DsdSyncDataSymbol[] getBssSymbols() {
        return bss_symbols.getArray(new DsdSyncDataSymbol[0], DsdSyncDataSymbol::new);
    }

    public DsdSyncRelocation[] getRelocations() {
        return relocations.getArray(new DsdSyncRelocation[0], DsdSyncRelocation::new);
    }
}
