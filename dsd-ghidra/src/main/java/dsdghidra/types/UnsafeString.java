package dsdghidra.types;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.List;

public class UnsafeString extends Structure {
    public Pointer ptr;

    @Override
    protected List<String> getFieldOrder() {
        return List.of("ptr");
    }

    public String getString() {
        return this.ptr.getString(0);
    }
}
