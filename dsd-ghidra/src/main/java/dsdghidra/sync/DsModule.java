package dsdghidra.sync;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DsModule {
    // Special keys for sectionMap
    public static final String COMBINED_CODE_KEY = "CODE";

    public final String name;
    private final Map<String, DsSection> sectionMap;

    public DsModule(String name) {
        this.name = name;
        this.sectionMap = new HashMap<>();
    }

    public void add(DsSection section) {
        sectionMap.put(section.name, section);
    }

    public DsSection get(String name) {
        return sectionMap.get(name);
    }

    public String toString(int indent) {
        String pad = new String(new char[indent]).replace('\0', ' ');
        String pad2 = new String(new char[indent + 2]).replace('\0', ' ');
        String pad4 = new String(new char[indent + 4]).replace('\0', ' ');

        List<String> sections = this
            .sectionMap
            .entrySet()
            .stream()
            .map(entry -> pad4 + entry.getKey() + ": " + entry.getValue().toString())
            .toList();

        return pad + "DsModule{\n" +
            pad2 + "name=" + name + ",\n" +
            pad2 + "sectionMap={\n" + String.join(",\n", sections) + "\n" +
            pad2 + "}\n" +
            pad + "}";
    }
}
