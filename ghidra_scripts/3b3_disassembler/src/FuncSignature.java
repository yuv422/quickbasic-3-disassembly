import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.util.List;

public record FuncSignature(List<Arg> args, RegWithType returnType) {
    public FuncSignature() {
        this(List.of(), null);
    }

    public FuncSignature(List<Arg> args) {
        this(args, null);
    }

    public void applyFuncSignature(Function function) {
//        function.updateFunction(null, );
    }
}
