package dsdghidra.dsd;

import ghidra.program.model.symbol.RefType;

public enum DsdRelocationKind {
    ArmCall,
    ThumbCall,
    ArmCallThumb,
    ThumbCallArm,
    ArmBranch,
    Load;

    public static final DsdRelocationKind[] VALUES = DsdRelocationKind.values();

    public RefType getRefType(boolean conditional) {
        switch (this) {
            case ArmCall, ThumbCall, ArmCallThumb, ThumbCallArm -> {
                return conditional ? RefType.CONDITIONAL_CALL : RefType.UNCONDITIONAL_CALL;
            }
            case ArmBranch -> {
                return conditional ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP;
            }
            case Load -> {
                return RefType.DATA;
            }
        }
        return null;
    }
}
