package dsdghidra.sync;

import dsdghidra.util.DataTypeUtil;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;

public class SyncRelocation {
    public final DsdSyncRelocation dsdRelocation;
    public final Address from;
    private final Program program;

    public SyncRelocation(Program program, DsSection dsSection, DsdSyncRelocation dsdRelocation) {
        Address from = dsSection.getAddress(dsdRelocation.from);

        this.dsdRelocation = dsdRelocation;
        this.from = from;
        this.program = program;
    }

    public boolean needsUpdate() {
        ReferenceManager referenceManager = program.getReferenceManager();
        Reference[] references = referenceManager.getReferencesFrom(from);

        switch (dsdRelocation.getModule()) {
            case None -> {
                return references.length > 0;
            }
            case Overlays -> {
                if (dsdRelocation.overlays.len != references.length) {
                    return true;
                }
                short[] overlays = dsdRelocation.overlays.getArray();
                for (Reference reference : references) {
                    if (reference.getToAddress().getOffset() != dsdRelocation.to) {
                        return true;
                    }

                    String addressSpaceName = reference.getToAddress().getAddressSpace().getName();
                    int toOverlay = DsAddressSpaces.parseOverlayNumber(addressSpaceName);
                    boolean found = false;
                    for (short overlay : overlays) {
                        if (toOverlay == overlay) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        return true;
                    }
                }
                return false;
            }
            case Main -> {
                if (references.length != 1) {
                    return true;
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return true;
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                return DsAddressSpaces.isMain(addressSpaceName);
            }
            case Itcm -> {
                if (references.length != 1) {
                    return true;
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return true;
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                return DsAddressSpaces.isItcm(addressSpaceName);
            }
            case Dtcm -> {
                if (references.length != 1) {
                    return true;
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return true;
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                return DsAddressSpaces.isDtcm(addressSpaceName);
            }
        }
        throw new MatchException("Unknown relocation type", null);
    }

    public boolean existsInGhidra() {
        ReferenceManager referenceManager = program.getReferenceManager();
        return referenceManager.getReferencesFrom(from).length > 0;
    }

    public void deleteExistingReferences() {
        ReferenceManager referenceManager = program.getReferenceManager();
        referenceManager.removeAllReferencesFrom(from);
    }

    public void addReferences(FlatProgramAPI api, DsModules dsModules) {
        switch (dsdRelocation.getModule()) {
            case None -> {
            }
            case Overlays -> {
                short[] array = dsdRelocation.overlays.getArray();
                for (int i = 0; i < array.length; i++) {
                    short id = array[i];
                    boolean primary = i == 0;
                    this.addReference(api, dsModules.getOverlay(id), primary);
                }
            }
            case Main -> {
                this.addReference(api, dsModules.main, true);
            }
            case Itcm -> {
                this.addReference(api, dsModules.itcm, true);
            }
            case Dtcm -> {
                this.addReference(api, dsModules.dtcm, true);
            }
        }
    }

    private void addReference(FlatProgramAPI api, DsModule toModule, boolean primary) {
        ReferenceManager referenceManager = program.getReferenceManager();
        DataType undefined4Type = DataTypeUtil.getUndefined4();

        DsSection dsSection = toModule.getSectionContaining(dsdRelocation.to);
        Address to = dsSection.getAddress(dsdRelocation.to);

        RefType refType = dsdRelocation.getKind().getRefType(dsdRelocation.conditional);

        Reference reference = referenceManager.addMemoryReference(from, to, refType, SourceType.USER_DEFINED, 0);
        referenceManager.setPrimary(reference, primary);

        try {
            api.createData(from, undefined4Type);
        } catch (CodeUnitInsertionException ignore) {
        }
    }
}
