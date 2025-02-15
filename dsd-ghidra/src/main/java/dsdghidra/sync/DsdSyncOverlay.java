package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.List;

public class DsdSyncOverlay extends Structure {
    public short id;
    public DsdSyncModule module;

    public DsdSyncOverlay() {
    }

    public DsdSyncOverlay(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("id", "module");
    }
}
