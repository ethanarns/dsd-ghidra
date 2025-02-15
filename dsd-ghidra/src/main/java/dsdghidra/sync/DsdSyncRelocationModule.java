package dsdghidra.sync;

public enum DsdSyncRelocationModule {
    None,
    Overlays,
    Main,
    Itcm,
    Dtcm;

    public static final DsdSyncRelocationModule[] VALUES = DsdSyncRelocationModule.values();
}
