package dsdghidra.sync;

import dsdghidra.DsdGhidraPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;

public class SyncDelinkFile {
    private final Program program;
    private final DsdSyncDelinkFile dsdDelinkFile;
    private final DsModule dsModule;

    public SyncDelinkFile(Program program, DsdSyncDelinkFile dsdDelinkFile, DsModule dsModule) {
        this.program = program;
        this.dsdDelinkFile = dsdDelinkFile;
        this.dsModule = dsModule;
    }

    private String getBookmarkCategory() {
        return dsModule.name;
    }

    private String getBookmarkComment(String sectionName) {
        return dsdDelinkFile.name.getString() + "(" + sectionName + ")";
    }

    public void addBookmarks() {
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        BookmarkType sectionBookmark = DsdGhidraPlugin.getBookmarkTypeSection();

        String category = getBookmarkCategory();

        for (DsdSyncBaseSection section : dsdDelinkFile.getSections()) {
            DsSection dsSection = dsModule.getSection(section);
            Address address = dsSection.getAddress(section.start_address);
            String sectionName = section.name.getString();
            String comment =getBookmarkComment(sectionName);

            bookmarkManager.setBookmark(address, sectionBookmark.getTypeString(), category, comment);
        }
    }
}
