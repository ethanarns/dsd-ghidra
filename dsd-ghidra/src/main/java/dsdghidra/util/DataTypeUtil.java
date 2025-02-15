package dsdghidra.util;

import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;

public final class DataTypeUtil {
    public static DataType getUndefined4() {
        BuiltInDataTypeManager builtInDataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        return builtInDataTypeManager.getDataType("/undefined4");
    }
}
