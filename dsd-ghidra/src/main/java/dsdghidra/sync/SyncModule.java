package dsdghidra.sync;

import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.util.exception.NotFoundException;

public class SyncModule {
    private final Program program;
    private final DsdSyncModule dsdModule;
    private final DsModule dsModule;

    public SyncModule(Program program, DsdSyncModule dsdModule, DsModule dsModule) {
        this.program = program;
        this.dsdModule = dsdModule;
        this.dsModule = dsModule;
    }

    public boolean needsUpdate() {
        if (!dsModule.isSplit()) {
            return true;
        }

        DsdSyncSection[] dsdSyncSections = dsdModule.getSections();
        if (dsModule.getSections().size() != dsdSyncSections.length) {
            return true;
        }

        for (DsdSyncSection dsdSyncSection : dsdSyncSections) {
            DsSection dsSection = dsModule.getSection(dsdSyncSection.base);
            if (dsSection == null) {
                return true;
            }
            if (!dsSection.matches(dsdSyncSection)) {
                return true;
            }
        }

        return false;
    }

    public void split()
    throws LockException, MemoryBlockException, NotFoundException {
        dsModule.split(program, dsdModule);
    }

    public void join()
    throws LockException, MemoryBlockException, NotFoundException {
        dsModule.join(program);
    }
}
