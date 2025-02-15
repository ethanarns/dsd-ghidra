package dsdghidra.sync;

import ghidra.program.model.mem.MemoryBlock;

import java.util.*;

public class DsAddressSpaces {
    public final DsAddressSpace main;
    public final DsAddressSpace mainBss;
    public final DsAddressSpace itcm;
    public final DsAddressSpace dtcm;
    public final DsAddressSpace dtcmBss;
    public final HashMap<Integer, DsAddressSpace> unknownAutoloads;
    public final HashMap<Integer, DsAddressSpace> unknownAutoloadsBss;
    private final DsAddressSpace[] overlays;
    private final DsAddressSpace[] overlaysBss;

    public DsAddressSpaces(MemoryBlock[] memoryBlocks) {
        DsAddressSpace main = null;
        DsAddressSpace mainBss = null;
        DsAddressSpace itcm = null;
        DsAddressSpace dtcm = null;
        DsAddressSpace dtcmBss = null;
        HashMap<Integer, DsAddressSpace> unknownAutoloads = new HashMap<>();
        HashMap<Integer, DsAddressSpace> unknownAutoloadsBss = new HashMap<>();
        ArrayList<DsAddressSpace> overlays = new ArrayList<>();
        ArrayList<DsAddressSpace> overlaysBss = new ArrayList<>();

        for (MemoryBlock memoryBlock : memoryBlocks) {
            String addressSpaceName = memoryBlock.getName();

            // dsd-ghidra
            if (addressSpaceName.startsWith("arm9_ov")) {
                if (addressSpaceName.endsWith(".bss")) {
                    String overlayNumberString = trimZeros(addressSpaceName, 7, -4);
                    addOverlay(overlaysBss, memoryBlock, overlayNumberString);
                } else {
                    String overlayNumberString = trimZeros(addressSpaceName, 7);
                    addOverlay(overlays, memoryBlock, overlayNumberString);
                }
            } else if (addressSpaceName.equals("arm9_main")) {
                main = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("arm9_main.bss")) {
                mainBss = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("itcm")) {
                itcm = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("dtcm")) {
                dtcm = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("dtcm.bss")) {
                dtcmBss = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.startsWith("autoload_")) {
                String autoloadAddressString;
                if (addressSpaceName.endsWith(".bss")) {
                    autoloadAddressString = trimZeros(addressSpaceName, 9, -4);
                } else {
                    autoloadAddressString = trimZeros(addressSpaceName, 9);
                }

                int autoloadAddress;
                try {
                    autoloadAddress = Integer.parseInt(autoloadAddressString);
                } catch (Exception ignore) {
                    continue;
                }

                if (addressSpaceName.endsWith(".bss")) {
                    unknownAutoloadsBss.put(autoloadAddress, new DsAddressSpace(memoryBlock));
                } else {
                    unknownAutoloads.put(autoloadAddress, new DsAddressSpace(memoryBlock));
                }
            }
            // NTRGhidra
            else if (addressSpaceName.startsWith("overlay_")) {
                String overlayNumberString = addressSpaceName.substring(8);
                if (overlayNumberString.startsWith("d_")) {
                    overlayNumberString = overlayNumberString.substring(2);
                }
                if (overlayNumberString.endsWith("_bss")) {
                    overlayNumberString = overlayNumberString.substring(0, overlayNumberString.length() - 4);
                    addOverlay(overlaysBss, memoryBlock, overlayNumberString);
                } else {
                    addOverlay(overlays, memoryBlock, overlayNumberString);
                }
            } else if (addressSpaceName.equals("ARM9_Main_Memory")) {
                main = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("ARM9_Main_Memory_bss")) {
                mainBss = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("ITCM")) {
                itcm = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("DTCM")) {
                dtcm = new DsAddressSpace(memoryBlock);
            } else if (addressSpaceName.equals("DTCM_bss")) {
                dtcmBss = new DsAddressSpace(memoryBlock);
            }
        }

        this.main = main;
        this.mainBss = mainBss;
        this.itcm = itcm;
        this.dtcm = dtcm;
        this.dtcmBss = dtcmBss;
        this.unknownAutoloads = unknownAutoloads;
        this.unknownAutoloadsBss = unknownAutoloadsBss;
        this.overlays = overlays.toArray(new DsAddressSpace[0]);
        this.overlaysBss = overlaysBss.toArray(new DsAddressSpace[0]);
    }

    private static String trimZeros(String string, int start) {
        return trimZeros(string, start, string.length());
    }

    private static String trimZeros(String string, int start, int end) {
        if (end < 0) {
            end = string.length() + end;
        }

        for (int i = start; i < end; i++) {
            if (string.charAt(i) != '0') {
                return string.substring(i, end);
            }
        }
        return string.substring(start, end);
    }

    private static void addOverlay(ArrayList<DsAddressSpace> overlays, MemoryBlock memoryBlock, String overlayNumberString) {
        int overlayNumber;
        try {
            overlayNumber = Integer.parseInt(overlayNumberString);
        } catch (Exception ignore) {
            return;
        }

        overlays.ensureCapacity(overlayNumber + 1);

        while (overlays.size() <= overlayNumber) {
            overlays.add(null);
        }
        overlays.set(overlayNumber, new DsAddressSpace(memoryBlock));
    }

    public static int parseOverlayNumber(String addressSpaceName) {
        String overlayNumberString;
        if (addressSpaceName.startsWith("arm9_ov")) {
            if (addressSpaceName.endsWith(".bss")) {
                overlayNumberString = trimZeros(addressSpaceName, 7, -4);
            } else {
                overlayNumberString = trimZeros(addressSpaceName, 7);
            }
        } else if (addressSpaceName.startsWith("overlay_")) {
            overlayNumberString = addressSpaceName.substring(8);
            if (overlayNumberString.startsWith("d_")) {
                overlayNumberString = overlayNumberString.substring(2);
            }
            if (overlayNumberString.endsWith("_bss")) {
                overlayNumberString = overlayNumberString.substring(0, overlayNumberString.length() - 4);
            }
        } else {
            return -1;
        }
        try {
            return Integer.parseInt(overlayNumberString);
        } catch (NumberFormatException ignore) {
            return -1;
        }
    }

    public static boolean isMain(String addressSpaceName) {
        return addressSpaceName.equals("arm9_main") ||
            addressSpaceName.equals("arm9_main.bss") ||
            addressSpaceName.equals("ARM9_Main_Memory") ||
            addressSpaceName.equals("ARM9_Main_Memory_bss");
    }

    public static boolean isItcm(String addressSpaceName) {
        return addressSpaceName.equals("itcm") ||
            addressSpaceName.equals("ITCM");
    }

    public static boolean isDtcm(String addressSpaceName) {
        return addressSpaceName.equals("dtcm") ||
            addressSpaceName.equals("dtcm.bss") ||
            addressSpaceName.equals("DTCM") ||
            addressSpaceName.equals("DTCM_bss");
    }

    public DsAddressSpace overlay(int id) {
        if (id < 0 || id >= this.overlays.length) {
            return null;
        }
        return this.overlays[id];
    }

    public DsAddressSpace overlayBss(int id) {
        if (id < 0 || id >= this.overlaysBss.length) {
            return null;
        }
        return this.overlaysBss[id];
    }
}
