public record RegWithType(Reg reg, BasicType type) {
    public static RegWithType bxFloat() {
        return new RegWithType(Reg.BX, BasicType.Float);
    }
    public static RegWithType bxString() {
        return new RegWithType(Reg.BX, BasicType.Str);
    }
    public static RegWithType dxString() {
        return new RegWithType(Reg.DX, BasicType.Str);
    }
    public static RegWithType bxInt() {
        return new RegWithType(Reg.BX, BasicType.Int);
    }
    public static RegWithType bxIntPtr() {
        return new RegWithType(Reg.BX, BasicType.IntPtr);
    }
}
