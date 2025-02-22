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
        this.syncModule(dsdSyncData.arm9, dsModules.main);
        for (DsdSyncAutoload autoload : dsdSyncData.getAutoloads()) {
            switch (autoload.getKind()) {
                case Itcm -> this.syncModule(autoload.module, dsModules.itcm);
                case Dtcm -> this.syncModule(autoload.module, dsModules.dtcm);
                case Unknown -> {
                    DsModule dsModule = dsModules.getAutoload(autoload.module.base_address);
                    if (dsModule == null) {
                        throw new Exception(
                            "No memory blocks for unknown autoload at base address " + Integer.toHexString(
                                autoload.module.base_address));
                    }
                    this.syncModule(autoload.module, dsModule);
                }
            }
        }
        for (DsdSyncOverlay overlay : dsdSyncData.getArm9Overlays()) {
            DsModule dsModule = dsModules.getOverlay(overlay.id);
            if (dsModule == null) {
                throw new Exception("No memory blocks for overlay " + overlay.id);
            }
            this.syncModule(overlay.module, dsModule);
        }
    }

    private void syncModule(DsdSyncModule dsdSyncModule, DsModule dsModule) throws Exception {
        for (DsdSyncSection section : dsdSyncModule.getSections()) {
            DsSection dsSection = dsModule.getSection(section.base.name.getString());
            this.removeSectionComments(dsSection);

            this.addSectionComment(section.base, dsModule, "");

            for (DsdSyncFunction function : section.getFunctions()) {
                this.updateFunction(function, dsSection);
            }
            for (DsdSyncDataSymbol dataSymbol : section.getSymbols()) {
                this.updateData(dataSymbol, dsSection);
            }
            for (DsdSyncRelocation relocation : section.getRelocations()) {
                this.updateReferences(relocation, dsSection);
            }
        }
        for (DsdSyncDelinkFile file : dsdSyncModule.getFiles()) {
            String fileName = file.name.getString();
            for (DsdSyncBaseSection section : file.getSections()) {
                this.addSectionComment(section, dsModule, fileName);
            }
        }

    }

    private void removeSectionComments(DsSection dsSection) {
        AddressSet addressSet = new AddressSet(dsSection.memoryBlock.getAddressRange());
        for (Address address : listing.getCommentAddressIterator(SECTION_COMMENT_TYPE, addressSet, true)) {
            if (!dryRun) {
                listing.clearComments(address, address.next());
            }
        }
    }

    private void addSectionComment(DsdSyncBaseSection section, DsModule dsModule, String fileName) throws Exception {
        DsSection dsSection = dsModule.getSection(section.name.getString());
        if (dsSection == null) {
            return;
        }
        Address start = dsSection.getAddress(section.start_address);
        if (start == null) {
            String error = "Section's address range does not match parent module '" + dsModule.name + "'\n";
            error += "Section: " + fileName + section.name.getString();
            error += "[" + Integer.toHexString(section.start_address);
            error += ".." + Integer.toHexString(section.end_address) + "]\n";
            error += "Parent: " + dsModule.name + dsSection.name;
            error += "[" + Integer.toHexString(dsSection.minAddress);
            error += ".." + Integer.toHexString(dsSection.maxAddress) + "]\n";
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

    private void updateFunction(DsdSyncFunction function, DsSection dsSection)
    throws InvalidInputException, DuplicateNameException, CodeUnitInsertionException, CircularDependencyException,
        OverlappingFunctionException {

        SyncFunction syncFunction = new SyncFunction(currentProgram, dsSection, function);

        Function ghidraFunction = syncFunction.getExistingGhidraFunction();
        if (ghidraFunction == null) {
            String mode = function.thumb ? "thumb" : "arm";
            println("Adding function " + syncFunction.symbolName.symbol + " (" + mode + ") at " + syncFunction.start);

            if (!dryRun) {
                syncFunction.createGhidraFunction(monitor);
            }
        } else {
            if (syncFunction.ghidraFunctionNeedsUpdate(ghidraFunction)) {
                println("Updating function " + syncFunction.symbolName.symbol + " at " + syncFunction.start);
                if (!dryRun) {
                    try {
                        syncFunction.updateGhidraFunction(ghidraFunction);
                    } catch (OverlappingFunctionException e) {
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

    private void updateData(DsdSyncDataSymbol dataSymbol, DsSection dsSection)
    throws InvalidInputException, DuplicateNameException {
        SyncDataSymbol syncDataSymbol = new SyncDataSymbol(currentProgram, dsSection, dataSymbol);

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

    private void updateReferences(DsdSyncRelocation relocation, DsSection dsSection) {
        SyncRelocation syncRelocation = new SyncRelocation(currentProgram, dsSection, relocation);

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
            syncRelocation.addReferences(this, dsModules);
        }
    }
}
