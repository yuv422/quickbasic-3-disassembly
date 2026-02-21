import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;

public record Arg(String name, RegWithType type) {
    public static Arg bxFloat(String name) {
        return new Arg(name, RegWithType.bxFloat());
    }
    public static Arg bxString(String name) {
        return new Arg(name, RegWithType.bxString());
    }
    public static Arg dxString(String name) {
        return new Arg(name, RegWithType.dxString());
    }
    public static Arg bxInt(String name) {
        return new Arg(name, RegWithType.bxInt());
    }
    public static Arg bxIntPtr(String name) {
        return new Arg(name, RegWithType.bxIntPtr());
    }
}
