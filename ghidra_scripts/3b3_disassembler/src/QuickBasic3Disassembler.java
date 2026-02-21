import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static ghidra.app.cmd.comments.SetCommentCmd.createComment;

public class QuickBasic3Disassembler extends GhidraScript {
    DataType byteDataType;
    DataType wordDataType;

    @Override
    protected void run() throws Exception {
        byteDataType = currentProgram.getDataTypeManager().getDataType("/byte");
        if (byteDataType == null) {
            byteDataType = ByteDataType.dataType;
        }
        wordDataType = currentProgram.getDataTypeManager().getDataType("/word");
        if (wordDataType == null) {
            print("Failed to get word datatype!");
        }
        Address currentAddr = currentProgram.getMemory().getMinAddress().add(0x40);
        createBrun30Segments(currentAddr);

        printf("min address = %s %s\n", currentAddr.toString(), byteDataType.getDataTypePath());
        if (getInstructionAt(currentAddr) != null) {
            currentAddr = currentAddress;
        }
        Disassembler disassembler = Disassembler.getDisassembler(currentProgram, new ConsoleTaskMonitor(), DisassemblerMessageListener.CONSOLE);

        disassembleFlow(currentAddr, disassembler);
    }

    void disassembleFlow(Address currentAddr, Disassembler disassembler) throws MemoryAccessException, CodeUnitInsertionException {
        boolean endReached = false;
        while (!endReached && getInstructionAt(currentAddr) == null) {
//            printf("Disassemble at %s\n", currentAddr);
            Address nextAddress = disassembleInstruction(disassembler, currentAddr);
            Instruction instr = getInstructionAt(currentAddr);
            if (instr != null && instr.toString().startsWith("INT ")) {
                Scalar scalar = (Scalar) instr.getOpObjects(0)[0];
                int intCode = (int)scalar.getValue();
                if (intCode == 0x3d || intCode == 0x3e || intCode == 0x3f) {
                    int commandByte = Byte.toUnsignedInt(currentProgram.getMemory().getByte(nextAddress));
                    String commandStr = getCommandString(intCode, commandByte);
                    if (commandStr.endsWith("_UNK")) {
                        printf("%s: basic command %s\n", currentAddr, commandStr);
                    }
                    currentProgram.getListing().createData(nextAddress, byteDataType);

                    createComment(currentProgram,
                            instr.getAddress(),
                            getCommandString(intCode, commandByte),
                            CommentType.EOL);

                    if (intCode == 0x3f && (commandByte == 0x5e || commandByte == 0x5d)) { // ON GOTO
                        nextAddress = handleOnGoto(disassembler, nextAddress);
                    } else {
                        nextAddress = nextAddress.add(getNumCommandBytes(intCode, commandByte, nextAddress)); // skip command byte
                    }
                    if (intCode == 0x3e && (commandByte == 2 || commandByte == 1)) {
                        endReached = true;
                        instr.setFlowOverride(FlowOverride.RETURN);
                    } else {
                        instr.setFallThrough(nextAddress);
                    }
                }
            } else if (instr != null && instr.toString().startsWith("INTB")) {
                int intCode = Integer.parseInt(instr.toString().substring(4,6), 16);
                Scalar scalar = (Scalar) instr.getOpObjects(0)[0];
                int commandByte = (int)scalar.getValue();
                String commandStr = getCommandString(intCode, commandByte);
                if (commandStr.endsWith("_UNK")) {
                    printf("%s: basic command %s\n", currentAddr, commandStr);
                }
//                currentProgram.getListing().createData(nextAddress, byteDataType);

                createComment(currentProgram,
                        instr.getAddress(),
                        getCommandString(intCode, commandByte),
                        CommentType.EOL);

                if (intCode == 0x3f && (commandByte == 0x5e || commandByte == 0x5d)) { // ON GOTO
                    nextAddress = handleOnGoto(disassembler, nextAddress.subtract(1));
                } else {
                    nextAddress = nextAddress.add(getNumCommandBytes(intCode, commandByte, nextAddress.subtract(1))-1); // skip command byte
                }
                if (intCode == 0x3e && (commandByte == 2 || commandByte == 1)) {
                    endReached = true;
                    instr.setFlowOverride(FlowOverride.RETURN);
                } else {
                    instr.setFallThrough(nextAddress);
                }
            } else {
                // TODO follow CALL and branch instructions
                if (instr.getFlowType().isJump()) {
                    if (instr.getFlowType().isUnConditional()) {
//                        printf("unconditionalJump at %s, %s\n", instr.getAddress(), instr);
                        nextAddress = instr.getFlows()[0];
//                    printf("Unconditional jump moving to %s\n", nextAddress.toString());
                    } else {
//                        printf("conditional jump at %s fall through %s\n", instr.getAddress(), nextAddress);
                        disassembleFlow(instr.getFlows()[0], disassembler);
                    }
                } else if (instr.getFlowType().isTerminal()) {
//                    printf("terminal instr at %s\n", instr.getAddress());
                    endReached = true;
                } else if (instr.getFlowType().isCall()) {
//                    printf("call at %s\n", instr.getAddress());
                    disassembleFlow(instr.getFlows()[0], disassembler);
                }
            }
            currentAddr = nextAddress;
        }
//        printf("done at %s\n", currentAddr);
    }

    Address handleOnGoto(Disassembler disassembler, Address commandByteAddress) throws MemoryAccessException, CodeUnitInsertionException {
        int numAddrs = Byte.toUnsignedInt(currentProgram.getMemory().getByte(commandByteAddress.add(1)));
        Address jumpTableAddr = commandByteAddress.add(2);
        for (int i = 0; i < numAddrs; i++) {
            currentProgram.getListing().createData(jumpTableAddr, wordDataType);
            Data jumpTarget = currentProgram.getListing().getDataAt(jumpTableAddr);
            int cs = ((SegmentedAddress)jumpTableAddr).getSegment();
            int offset = (int)((Scalar)jumpTarget.getValue()).getValue();
//            printf("jumpTarget: %x:%x\n", cs, offset + 0x10);
            Address destAddr = ((SegmentedAddressSpace)jumpTableAddr.getAddressSpace()).getAddress(cs, offset + 0x10);
            this.currentProgram.getReferenceManager().addMemoryReference(jumpTableAddr, destAddr, RefType.DATA, SourceType.USER_DEFINED, 0);
            disassembleFlow(destAddr, disassembler);
            jumpTableAddr = jumpTableAddr.add(2);
//            printf("jumpTargetAddr %x:%s %s\n", cs, jumpTarget.getValue().toString(), jumpTarget.getValueClass().getSimpleName());
        }

        return commandByteAddress.add(numAddrs * 2 + 2);
    }

    int getNumCommandBytes(int intCode, int commandByte, Address commandByteAddress) throws MemoryAccessException {
        switch (intCode) {
            case 0x3d : return Int3DEnum.findByCmd(commandByte).cmdLength;
            case 0x3e : return Int3EEnum.findByCmd(commandByte).cmdLength;
            case 0x3f : {
                if (commandByte == 0xb7) {
                    int numArgs = Byte.toUnsignedInt(currentProgram.getMemory().getByte(commandByteAddress.add(1)));
                    return numArgs + 2;
                }
                return Int3FEnum.findByCmd(commandByte).cmdLength;
            }
        }
        return 1;
    }

    String getCommandString(int intCode, int commandByte) {
        switch (intCode) {
            case 0x3d : return Int3DEnum.findByCmd(commandByte).name();
            case 0x3e : return Int3EEnum.findByCmd(commandByte).name();
            case 0x3f : return Int3FEnum.findByCmd(commandByte).name();
        }
        return "";
    }
    Address disassembleInstruction(Disassembler d, Address a) {
        AddressSet as = d.disassemble(a, new AddressSet(a), false);
        if (as.getMaxAddress() == null) {
            printf("issue at %s\n\n", a);
        }
        a = as.getMaxAddress().add(1);
        return a;
    }

    void createBrun30Segments(Address currentAddr) throws AddressOverflowException, LockException, CancelledException, MemoryConflictException, InvalidInputException, OverlappingFunctionException, DuplicateNameException {
        createSegment("BRun30Int3D", 0x9000, currentAddress, Arrays.stream(Int3DEnum.values()).map(it -> new Pair<>(it.name(), it.funcSignature)).toList());
        createSegment("BRun30Int3E", 0x9010, currentAddress, Arrays.stream(Int3EEnum.values()).map(it -> new Pair<>(it.name(), it.funcSignature)).toList());
        createSegment("BRun30Int3F", 0x9020, currentAddress, Arrays.stream(Int3FEnum.values()).map(it -> new Pair<>(it.name(), it.funcSignature)).toList());
    }

    void createSegment(String name, int segment, Address currentAddress, List<Pair<String, FuncSignature>> funcs) throws AddressOverflowException, LockException, CancelledException, MemoryConflictException, InvalidInputException, OverlappingFunctionException, DuplicateNameException {
        if (currentProgram.getMemory().getBlock(name) == null) {
            currentProgram.getMemory().createInitializedBlock(
                    name,
                    (Address)((SegmentedAddressSpace)currentAddress.getAddressSpace()).getAddress(segment, 0),
                    256L,
                    (byte)0xCB, // RETF
                    null,
                    false
            );
        }

        for (int i = 0; i < funcs.size(); i++) {
            String opName = funcs.get(i).first;
            FuncSignature sig = funcs.get(i).second;
            Address funcAddress = ((SegmentedAddressSpace)currentAddress.getAddressSpace()).getAddress(segment, i+1);
            if (currentProgram.getFunctionManager().getFunctionAt(funcAddress) != null) {
                currentProgram.getFunctionManager().removeFunction(funcAddress);
            }
            currentProgram.getFunctionManager().createFunction(opName, funcAddress, new AddressSet(funcAddress), SourceType.USER_DEFINED);
            applyFuncSignature(currentProgram.getFunctionManager().getFunctionAt(funcAddress), sig);
        }
    }

    public void applyFuncSignature(Function function, FuncSignature funcSignature) throws InvalidInputException, DuplicateNameException {
        List<Variable> funcVars = funcSignature.args().stream().map( arg -> {
            final DataType dt = getDataType(arg.type());
            try {
                Variable p = new ParameterImpl(
                        arg.name(),
                        dt,
                        new VariableStorage(currentProgram.getDataTypeManager().getProgramArchitecture(), currentProgram.getProgramContext().getRegister(arg.type().reg().name())),
                        currentProgram);
                return p;
            } catch (InvalidInputException e) {
                throw new RuntimeException(e);
            }
        }).toList();


        function.updateFunction(null, getReturnVar(funcSignature.returnType()), funcVars, Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
    }

    Variable getReturnVar(RegWithType type) throws InvalidInputException {
        if (type == null) return new ReturnParameterImpl(VoidDataType.dataType, currentProgram);

        return new ReturnParameterImpl(getDataType(type), currentProgram.getProgramContext().getRegister(type.reg().name()), currentProgram);
    }

    DataType getDataType(RegWithType type) {
        switch (type.type()) {
            case Int -> {
                return  WordDataType.dataType;
            }
            case IntPtr -> {
                return  Pointer16DataType.getPointer(WordDataType.dataType, 2);
            }
            case Float -> {
                return Pointer16DataType.getPointer(Float4DataType.dataType, 2);
            }
            case Double -> {
                return Pointer16DataType.getPointer(Float8DataType.dataType, 2);
            }
            case Str -> {
                return Pointer16DataType.getPointer(CharDataType.dataType, 2);
            }
        }

        return null;
    }
}
