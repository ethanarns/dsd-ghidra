package dsdghidra;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.BookmarkManager;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.Objects;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "Plugin for dsd-ghidra",
    description = "Plugin for dsd-ghidra"
)
public class DsdGhidraPlugin extends ProgramPlugin {
    public static final String SECTION_BOOKMARK = "DSD_SECTION";
    public static final String DELINK_FILE_BOOKMARK = "DSD_DELINK_FILE";

    private final Icon sectionIcon;
    private final Icon delinkFileIcon;

    public DsdGhidraPlugin(PluginTool plugintool) {
        super(plugintool);

        URL sectionIconUrl = DsdGhidraPlugin.class.getClassLoader().getResource("images/bookmark_section.png");
        URL delinkFileIconUrl = DsdGhidraPlugin.class.getClassLoader().getResource("images/bookmark_delink_file.png");

        Objects.requireNonNull(sectionIconUrl);
        Objects.requireNonNull(delinkFileIconUrl);

        this.sectionIcon = new ImageIcon(sectionIconUrl);
        this.delinkFileIcon = new ImageIcon(delinkFileIconUrl);
    }

    public void init() {
        super.init();

        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        bookmarkManager.defineType(SECTION_BOOKMARK, sectionIcon, new Color(0x6abe30), 0);
        bookmarkManager.defineType(DELINK_FILE_BOOKMARK, delinkFileIcon, new Color(0x0095e9), 0);
    }
}
