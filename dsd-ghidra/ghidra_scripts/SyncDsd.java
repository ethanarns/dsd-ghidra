//Imports symbols and relocations from dsd into this Ghidra project.
//@author Aetias
//@category dsd
//@keybinding
//@menupath Analysis.Sync DSD
//@toolbar sync.png

import dsdghidra.sync.DsAddressSpace;
import dsdghidra.sync.DsAddressSpaces;
import dialog.DsdConfigChooser;
import dsdghidra.DsdGhidra;
import dsdghidra.sync.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.File;
import java.io.IOException;

public class SyncDsd extends GhidraScript {
    private static final int SECTION_COMMENT_TYPE = CodeUnit.PLATE_COMMENT;

    private boolean dryRun = false;

    private Listing listing;
    private DsAddressSpaces dsAddressSpaces;
    private Register thumbRegister;
    private DsModules dsModules;

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.SUSPENDED;
    }

    @Override
    protected void run() throws Exception {
        this.listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] memoryBlocks = memory.getBlocks();
        this.dsAddressSpaces = new DsAddressSpaces(memoryBlocks);
        ProgramContext programContext = currentProgram.getProgramContext();
        this.thumbRegister = programContext.getRegister("TMode");
        this.dsModules = new DsModules(memory);
//        this.println(this.dsModules.toString(0));

        DsdConfigChooser dsdConfigChooser = new DsdConfigChooser(null, "Begin sync", propertiesFileParams);
        File file = dsdConfigChooser.getSelectedFile();
        dsdConfigChooser.dispose();
        if (dsdConfigChooser.wasCancelled()) {
            throw new CancelledException();
        }
        dryRun = dsdConfigChooser.isDryRun();

        DsdSyncData dsdSyncData = new DsdSyncData();
        if (!DsdGhidra.INSTANCE.get_dsd_sync_data(file.getPath(), dsdSyncData)) {
            throw new IOException("Failed to get sync data from dsd-ghidra");
        }

        try {
            this.doSync(dsdSyncData);
        } finally {
            DsdGhidra.INSTANCE.free_dsd_sync_data(dsdSyncData);
        }
    }

    private void doSync(DsdSyncData dsdSyncData) throws Exception {
        this.syncModule(dsdSyncData.arm9, dsAddressSpaces.main, dsAddressSpaces.mainBss, "arm9_main");
        for (DsdSyncAutoload autoload : dsdSyncData.getAutoloads()) {
            DsAddressSpace codeSpace = null;
            DsAddressSpace bssSpace = null;
            String moduleName = null;
            switch (autoload.getKind()) {
                case Itcm -> {
                    codeSpace = dsAddressSpaces.itcm;
                    moduleName = "itcm";
                }
                case Dtcm -> {
                    codeSpace = dsAddressSpaces.dtcm;
                    bssSpace = dsAddressSpaces.dtcmBss;
                    moduleName = "dtcm";
                }
                case Unknown -> {
                    codeSpace = dsAddressSpaces.unknownAutoloads.get(autoload.module.base_address);
                    bssSpace = dsAddressSpaces.unknownAutoloadsBss.get(autoload.module.base_address);
                    if (codeSpace == null && bssSpace == null) {
                        throw new Exception(
                            "No memory blocks for unknown autoload at base address " + Integer.toHexString(
                                autoload.module.base_address));
                    }
                    moduleName = "autoload_" + Integer.toHexString(autoload.module.base_address);
                }
            }
            this.syncModule(autoload.module, codeSpace, bssSpace, moduleName);
        }
        for (DsdSyncOverlay overlay : dsdSyncData.getArm9Overlays()) {
            DsAddressSpace codeSpace = dsAddressSpaces.overlay(overlay.id);
            DsAddressSpace bssSpace = dsAddressSpaces.overlayBss(overlay.id);
            if (codeSpace == null && bssSpace == null) {
                throw new Exception("No memory blocks for overlay " + overlay.id);
            }
            String moduleName = String.format("arm9_ov%03d", overlay.id);
            this.syncModule(overlay.module, codeSpace, bssSpace, moduleName);
        }
    }

    private void syncModule(DsdSyncModule dsdSyncModule, DsAddressSpace codeSpace, DsAddressSpace bssSpace,
        String moduleName
    ) throws Exception {
        this.removeSectionComments(codeSpace);
        this.removeSectionComments(bssSpace);
        for (DsdSyncSection section : dsdSyncModule.getSections()) {
            this.addSectionComment(section, codeSpace, bssSpace, moduleName, "");
        }
        for (DsdSyncDelinkFile file : dsdSyncModule.getFiles()) {
            String fileName = file.name.getString();
            for (DsdSyncSection section : file.getSections()) {
                this.addSectionComment(section, codeSpace, bssSpace, moduleName, fileName);
            }
        }

        for (DsdSyncFunction function : dsdSyncModule.getFunctions()) {
            this.updateFunction(function, codeSpace);
        }

        for (DsdSyncDataSymbol dataSymbol : dsdSyncModule.getDataSymbols()) {
            this.updateData(dataSymbol, codeSpace);
        }
        for (DsdSyncDataSymbol bssSymbol : dsdSyncModule.getBssSymbols()) {
            this.updateData(bssSymbol, bssSpace);
        }

        for (DsdSyncRelocation relocation : dsdSyncModule.getRelocations()) {
            this.updateReferences(relocation, codeSpace);
        }
    }

    private void removeSectionComments(DsAddressSpace addressSpace) {
        if (addressSpace == null) {
            return;
        }
        AddressSet addressSet = new AddressSet(addressSpace.addressSpace.getMinAddress(),
            addressSpace.addressSpace.getMaxAddress()
        );
        for (Address address : listing.getCommentAddressIterator(SECTION_COMMENT_TYPE, addressSet, true)) {
            if (!dryRun) {
                listing.clearComments(address, address.next());
            }
        }
    }

    private void addSectionComment(DsdSyncSection section, DsAddressSpace codeSpace, DsAddressSpace bssSpace,
        String moduleName, String fileName
    ) throws Exception {
        DsAddressSpace addressSpace = section.getKind().isBss() ? bssSpace : codeSpace;
        if (addressSpace == null) {
            return;
        }
        Address start = addressSpace.fromAbsolute(section.start_address);
        if (start == null) {
            String error = "Section's address range does not match parent module '" + moduleName + "'\n";
            error += "Section: " + fileName + section.name.getString();
            error += "[" + Integer.toHexString(section.start_address);
            error += ".." + Integer.toHexString(section.end_address) + "]\n";
            error += "Parent: " + moduleName;
            error += "[" + Integer.toHexString(addressSpace.minValue);
            error += ".." + Integer.toHexString(addressSpace.maxValue) + "]\n";
            throw new Exception(error);
        }

        String comment = "Start of section " + section.name.getString();
        if (!fileName.isEmpty()) {
            comment += "(" + fileName + ")";
        }

        if (!dryRun) {
            listing.setComment(start, SECTION_COMMENT_TYPE, comment);
        }
    }

    private void updateFunction(DsdSyncFunction function, DsAddressSpace codeSpace)
    throws InvalidInputException, DuplicateNameException, CodeUnitInsertionException, CircularDependencyException,
        OverlappingFunctionException {

        SyncFunction syncFunction = new SyncFunction(currentProgram, codeSpace, function);

        Function ghidraFunction = syncFunction.getExistingGhidraFunction();
        if (ghidraFunction == null) {
            String mode = function.thumb ? "thumb" : "arm";
            println("Adding function " + syncFunction.symbolName.symbol + " (" + mode + ") at " + syncFunction.start);

            if (!dryRun) {
                syncFunction.createGhidraFunction(monitor);
            }
        } else {
            if (syncFunction.ghidraFunctionNeedsUpdate(ghidraFunction)) {
                println(
                    "Updating function " + syncFunction.symbolName.symbol + " at " + syncFunction.start);
                if (!dryRun) {
                    try {
                        syncFunction.updateGhidraFunction(ghidraFunction);
                    }
                    catch(OverlappingFunctionException e) {
                        this.printerr("Failed to update function size: " + e.getMessage());
                    }
                }
            }
        }

        if (!dryRun) {
            syncFunction.definePoolConstants(this);
            syncFunction.disassemble(thumbRegister, monitor);
            syncFunction.referPoolConstants(this);
        }
    }

    private void updateData(DsdSyncDataSymbol dataSymbol, DsAddressSpace addressSpace)
    throws InvalidInputException, DuplicateNameException {
        SyncDataSymbol syncDataSymbol = new SyncDataSymbol(currentProgram, addressSpace, dataSymbol);

        boolean needsUpdate = syncDataSymbol.checkNeedsUpdate();
        String currentName = syncDataSymbol.getCurrentLabel();
        boolean exists = currentName != null;

        if (exists) {
            if (needsUpdate) {
                if (!dryRun) {
                    syncDataSymbol.deleteExistingLabels();
                }
                println(
                    "Updating data " + currentName + " at " + syncDataSymbol.address + " to name " + syncDataSymbol.symbolName.symbol);
            } else {
                return;
            }
        } else {
            println("Adding data " + syncDataSymbol.symbolName.symbol + " at " + syncDataSymbol.address);
        }

        if (!dryRun) {
            syncDataSymbol.createLabel();
            syncDataSymbol.defineData(this);
        }
    }

    private void updateReferences(DsdSyncRelocation relocation, DsAddressSpace codeSpace) {
        SyncRelocation syncRelocation = new SyncRelocation(currentProgram, codeSpace, relocation);

        if (syncRelocation.needsUpdate()) {
            println("Updating references from " + syncRelocation.from);
            if (!dryRun) {
                syncRelocation.deleteExistingReferences();
            }
        } else if (!syncRelocation.existsInGhidra()) {
            println("Adding references from " + syncRelocation.from);
        } else {
            return;
        }

        if (!dryRun) {
            syncRelocation.addReferences(this, dsAddressSpaces);
        }
    }
}
