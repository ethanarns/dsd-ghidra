package dsdghidra;

import ghidra.framework.plugintool.util.PluginPackage;

@SuppressWarnings("unused")
public class DsdPluginPackage extends PluginPackage {
    public static final String NAME = "dsd-ghidra";

    public DsdPluginPackage() {
        super(NAME, null, "These plugins should be enabled for use with dsd-ghidra scripts", FEATURE_PRIORITY);
    }
}
