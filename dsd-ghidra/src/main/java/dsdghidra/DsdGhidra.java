package dsdghidra;

import com.sun.jna.Native;
import com.sun.jna.Library;
import dsdghidra.loader.DsRomLoaderData;
import dsdghidra.sync.DsdSyncData;

public interface DsdGhidra extends Library {
    @SuppressWarnings("deprecation")
    DsdGhidra INSTANCE = Native.loadLibrary("dsd_ghidra", DsdGhidra.class);

    boolean is_valid_ds_rom(byte[] bytes, int length);

    boolean get_loader_data(byte[] bytes, int length, DsRomLoaderData data);

    void free_loader_data(DsRomLoaderData data);

    boolean get_dsd_sync_data(String config_path, DsdSyncData data);

    void free_dsd_sync_data(DsdSyncData data);
}
