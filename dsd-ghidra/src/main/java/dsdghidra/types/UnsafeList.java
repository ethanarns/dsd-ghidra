package dsdghidra.types;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

public class UnsafeList<T extends Structure> extends Structure {
    public Pointer ptr;
    public int len;

    @Override
    protected List<String> getFieldOrder() {
        return List.of("ptr", "len");
    }

    public T[] getArray(T[] emptyArray, Function<Pointer, T> factory) {
        if (ptr == null) {
            return emptyArray;
        }
        T[] array = Arrays.copyOf(emptyArray, len);
        Pointer pointer = ptr;
        for (int i = 0; i < len; i++) {
            array[i] = factory.apply(pointer);
            pointer = pointer.share(array[i].size());
        }
        return array;
    }
}
