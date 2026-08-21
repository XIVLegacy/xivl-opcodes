// xivl-opcodes - bounded retail zone-dispatch observation exporter
// Copyright (C) 2026 XIVLegacy Dev Team
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This script is intentionally decompiler-free. It validates one contiguous
// dispatcher/table data flow, follows the selected case body, derives the
// callback slot from its memory operand, and writes only the private
// observation contract.
//
// Required environment variables:
//   XIVL_RETAIL_DISPATCHER_VA
//   XIVL_RETAIL_OPCODE
//   XIVL_RETAIL_BYTE_TABLE_VA
//   XIVL_RETAIL_DWORD_TABLE_VA
//   XIVL_RETAIL_OBSERVATIONS_OUT
//@category XIVLegacy

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Locale;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.GhidraProgramUtilities;

public class ExportZoneDispatchRoute extends GhidraScript {

    private static final String CHECK_ID = "zone-dispatch-0x018d-slot-v1";
    private static final String PROGRAM_NAME = "ffxivgame.exe";
    private static final long IMAGE_BASE = 0x00400000L;
    private static final String LANGUAGE_ID = "x86:LE:32:default";
    private static final String COMPILER_SPEC_ID = "windows";

    private static final long FIXED_DISPATCHER_VA = 0x00dbfd10L;
    private static final int FIXED_OPCODE = 0x018d;
    private static final long FIXED_BYTE_TABLE_VA = 0x00dc1274L;
    private static final long FIXED_DWORD_TABLE_VA = 0x00dc0f5cL;
    private static final int OPCODE_BASE = 1;
    private static final int WORD_OFFSET = 2;
    private static final int PAYLOAD_OFFSET = 0x10;
    private static final int CASE_RETURN_BYTES = 0x8;

    private static final class DispatcherFlow {
        final int opcodeBase;
        final int maximumNormalizedOpcode;

        DispatcherFlow(int opcodeBase, int maximumNormalizedOpcode) {
            this.opcodeBase = opcodeBase;
            this.maximumNormalizedOpcode = maximumNormalizedOpcode;
        }
    }

    private static final class RouteObservation {
        final long byteTableEntryVa;
        final int caseIndex;
        final int callbackSlot;

        RouteObservation(long byteTableEntryVa, int caseIndex,
                         int callbackSlot) {
            this.byteTableEntryVa = byteTableEntryVa;
            this.caseIndex = caseIndex;
            this.callbackSlot = callbackSlot;
        }
    }

    @Override
    public void run() throws Exception {
        String outputPath = requireOutputPath();
        checkNotCancelled();

        long dispatcherVa = requireFixedAddress(
            "XIVL_RETAIL_DISPATCHER_VA", FIXED_DISPATCHER_VA);
        int opcode = requireFixedOpcode();
        long byteTableVa = requireFixedAddress(
            "XIVL_RETAIL_BYTE_TABLE_VA", FIXED_BYTE_TABLE_VA);
        long dwordTableVa = requireFixedAddress(
            "XIVL_RETAIL_DWORD_TABLE_VA", FIXED_DWORD_TABLE_VA);

        validateProgram();
        checkNotCancelled();

        Function dispatcher = validateDispatcherOwner(dispatcherVa);
        DispatcherFlow flow = validateDispatcherFlow(
            dispatcher, dispatcherVa, byteTableVa, dwordTableVa, opcode);
        require(flow.opcodeBase == OPCODE_BASE, "opcode base mismatch");
        require(opcode >= flow.opcodeBase &&
                opcode - flow.opcodeBase <= flow.maximumNormalizedOpcode,
                "opcode is outside dispatcher bounds");

        long byteTableEntryVa = byteTableVa + opcode - flow.opcodeBase;
        int caseIndex = readUnsignedByte(byteTableEntryVa);
        long dwordEntryVa = dwordTableVa + ((long) caseIndex * 4L);
        long caseBodyVa = readUnsignedDword(dwordEntryVa);
        int callbackSlot = validateCaseBody(dispatcher, caseBodyVa);

        checkNotCancelled();
        String json = buildObservation(dispatcherVa, opcode, byteTableVa,
            dwordTableVa, new RouteObservation(byteTableEntryVa, caseIndex,
                                               callbackSlot));
        writeAtomically(outputPath, json);
        checkNotCancelled();
    }

    private String requireOutputPath() {
        String raw = System.getenv("XIVL_RETAIL_OBSERVATIONS_OUT");
        if (raw == null || raw.trim().isEmpty()) {
            throw new IllegalArgumentException(
                "XIVL_RETAIL_OBSERVATIONS_OUT is required");
        }
        return raw.trim();
    }

    private long requireFixedAddress(String name, long expected) {
        String raw = requiredEnvironment(name);
        require(raw.matches("0x[0-9a-f]{8}"), name + " is malformed");
        long value = Long.parseLong(raw.substring(2), 16);
        require(value == expected, name + " is not the approved locator");
        return value;
    }

    private int requireFixedOpcode() {
        String raw = requiredEnvironment("XIVL_RETAIL_OPCODE");
        require(raw.matches("0x[0-9a-f]{4}"),
            "XIVL_RETAIL_OPCODE is malformed");
        int value = Integer.parseInt(raw.substring(2), 16);
        require(value == FIXED_OPCODE,
            "XIVL_RETAIL_OPCODE is not the approved opcode");
        return value;
    }

    private String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value.trim();
    }

    private void validateProgram() {
        require(currentProgram != null, "program unavailable");
        require(PROGRAM_NAME.equals(currentProgram.getName()),
            "program identity mismatch");
        require(currentProgram.getImageBase() != null &&
                currentProgram.getImageBase().getOffset() == IMAGE_BASE,
            "image base mismatch");
        require(currentProgram.getLanguageID() != null &&
                LANGUAGE_ID.equals(currentProgram.getLanguageID().getIdAsString()),
            "language mismatch");

        CompilerSpec compilerSpec = currentProgram.getCompilerSpec();
        require(compilerSpec != null && compilerSpec.getCompilerSpecID() != null &&
                COMPILER_SPEC_ID.equals(
                    compilerSpec.getCompilerSpecID().getIdAsString()),
            "compiler spec mismatch");
        require(GhidraProgramUtilities.isAnalyzed(currentProgram),
            "analysis incomplete");
    }

    private Function validateDispatcherOwner(long dispatcherVa) {
        Address dispatcherAddress = address(dispatcherVa);
        FunctionManager functions = currentProgram.getFunctionManager();
        Function dispatcher = functions.getFunctionAt(dispatcherAddress);
        require(dispatcher != null &&
                dispatcher.getEntryPoint().equals(dispatcherAddress),
            "dispatcher function missing");
        require(dispatcher.getBody().contains(dispatcherAddress),
            "dispatcher body mismatch");
        return dispatcher;
    }

    private DispatcherFlow validateDispatcherFlow(Function dispatcher,
                                                   long dispatcherVa,
                                                   long byteTableVa,
                                                   long dwordTableVa,
                                                   int opcode) {
        Listing listing = currentProgram.getListing();
        Instruction cursor = listing.getInstructionAt(address(dispatcherVa));
        require(cursor != null, "dispatcher instruction missing");

        Instruction opcodeLoad = null;
        int byteReferences = 0;
        int dwordReferences = 0;
        int scanned = 0;
        while (cursor != null && dispatcher.getBody().contains(cursor.getAddress())) {
            checkNotCancelled();
            if (isOpcodeLoad(cursor)) {
                require(opcodeLoad == null, "duplicate opcode load");
                opcodeLoad = cursor;
            }
            if (hasScalar(cursor, byteTableVa)) {
                byteReferences++;
            }
            if (hasScalar(cursor, dwordTableVa)) {
                dwordReferences++;
            }
            cursor = listing.getInstructionAfter(cursor.getAddress());
            if (++scanned > 4096) {
                throw new IllegalStateException("dispatcher scan limit exceeded");
            }
        }

        require(opcodeLoad != null, "opcode load missing");
        require(byteReferences == 1, "byte table reference is not unique");
        require(dwordReferences == 1, "dword table reference is not unique");
        validateDispatcherPacketPath(dispatcher, opcodeLoad);

        Instruction normalized = nextContiguous(opcodeLoad, dispatcher);
        int opcodeBase = validateNormalization(normalized);
        Instruction bound = nextContiguous(normalized, dispatcher);
        int maximumNormalizedOpcode = validateBound(bound, opcodeBase, opcode);
        Instruction branch = nextContiguous(bound, dispatcher);
        require("JA".equalsIgnoreCase(branch.getMnemonicString()),
            "dispatcher bound branch mismatch");
        require(branch.getFlowType() != null && branch.getFlowType().isJump(),
            "dispatcher bound flow mismatch");

        Instruction byteLoad = nextContiguous(branch, dispatcher);
        validateByteTableLoad(byteLoad, byteTableVa);
        Instruction jump = nextContiguous(byteLoad, dispatcher);
        validateDwordTableJump(jump, dwordTableVa);
        return new DispatcherFlow(opcodeBase, maximumNormalizedOpcode);
    }

    private void validateDispatcherPacketPath(Function dispatcher,
                                              Instruction opcodeLoad) {
        Instruction saved = previousContiguous(opcodeLoad, dispatcher);
        validatePush(saved, "ESI");
        Instruction headerField = previousContiguous(saved, dispatcher);
        validateLoadRegister(headerField, "EAX", "EAX", 0x24L);
        Instruction header = previousContiguous(headerField, dispatcher);
        validateLoadRegister(header, "EAX", "EDX", 0x8L);
        Instruction packet = previousContiguous(header, dispatcher);
        validateLoadRegister(packet, "EDX", "ESP", 0x8L);
    }

    private boolean isOpcodeLoad(Instruction instruction) {
        if (!"MOVZX".equalsIgnoreCase(instruction.getMnemonicString()) ||
                instruction.getNumOperands() != 2 ||
                !singleRegister(instruction.getOpObjects(0), "ESI")) {
            return false;
        }
        Object[] source = instruction.getOpObjects(1);
        int registers = 0;
        int offsets = 0;
        for (Object object : source) {
            if (object instanceof Register &&
                    "EAX".equalsIgnoreCase(((Register) object).getName())) {
                registers++;
            }
            else if (object instanceof Scalar &&
                     ((Scalar) object).getUnsignedValue() == WORD_OFFSET) {
                offsets++;
            }
            else {
                return false;
            }
        }
        return registers == 1 && offsets == 1 && hasLoadWidth(instruction, 2);
    }

    private int validateNormalization(Instruction instruction) {
        String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
        require(("ADD".equals(mnemonic) || "SUB".equals(mnemonic)) &&
                instruction.getNumOperands() == 2 &&
                singleRegister(instruction.getOpObjects(0), "ESI"),
            "opcode normalization shape mismatch");
        Object[] objects = instruction.getOpObjects(1);
        require(objects.length == 1 && objects[0] instanceof Scalar,
            "opcode normalization immediate mismatch");
        Scalar scalar = (Scalar) objects[0];
        if ("ADD".equals(mnemonic)) {
            require(scalar.getSignedValue() == -OPCODE_BASE,
                "opcode normalization value mismatch");
        }
        else {
            require(scalar.getUnsignedValue() == OPCODE_BASE,
                "opcode normalization value mismatch");
        }
        return OPCODE_BASE;
    }

    private int validateBound(Instruction instruction, int opcodeBase,
                              int opcode) {
        require("CMP".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 2 &&
                singleRegister(instruction.getOpObjects(0), "ESI"),
            "opcode bound shape mismatch");
        Object[] objects = instruction.getOpObjects(1);
        require(objects.length == 1 && objects[0] instanceof Scalar,
            "opcode bound immediate mismatch");
        long maximum = ((Scalar) objects[0]).getUnsignedValue();
        require(maximum <= Integer.MAX_VALUE && maximum >= 0,
            "opcode bound range mismatch");
        require(opcode >= opcodeBase && opcode - opcodeBase <= maximum,
            "approved opcode fails dispatcher bound");
        return (int) maximum;
    }

    private void validateByteTableLoad(Instruction instruction, long tableVa) {
        require("MOVZX".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 2 &&
                singleRegister(instruction.getOpObjects(0), "ESI"),
            "byte table load shape mismatch");
        require(memoryOperand(instruction.getOpObjects(1), "ESI", tableVa),
            "byte table operand mismatch");
        require(hasLoadWidth(instruction, 1), "byte table width mismatch");
    }

    private void validateDwordTableJump(Instruction instruction, long tableVa) {
        require("JMP".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 1,
            "dword table jump shape mismatch");
        require(instruction.getFlowType() != null &&
                instruction.getFlowType().isJump(),
            "dword table jump flow mismatch");
        RefType referenceType = instruction.getOperandRefType(0);
        require(referenceType != null && referenceType.isIndirect(),
            "dword table jump is not indirect");
        require(scaledMemoryOperand(instruction.getOpObjects(0), tableVa),
            "dword table operand mismatch");
        int branches = 0;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.BRANCHIND) {
                branches++;
            }
        }
        require(branches == 1, "dword table branch data flow mismatch");
    }

    private int validateCaseBody(Function dispatcher, long caseBodyVa)
            throws Exception {
        Memory memory = currentProgram.getMemory();
        Address caseAddress = address(caseBodyVa);
        MemoryBlock block = memory.getBlock(caseAddress);
        require(block != null && block.isExecute(),
            "case body is not executable memory");
        require(dispatcher.getBody().contains(caseAddress),
            "case body is outside dispatcher");

        Listing listing = currentProgram.getListing();
        Instruction[] body = new Instruction[10];
        body[0] = listing.getInstructionAt(caseAddress);
        require(body[0] != null, "case body instruction missing");
        for (int i = 1; i < body.length; i++) {
            checkNotCancelled();
            body[i] = nextContiguous(body[i - 1], dispatcher);
        }

        validateLoadRegister(body[0], "ESI", "ECX", 0L);
        validateAdd(body[1], "EAX", PAYLOAD_OFFSET);
        validatePush(body[2], "EAX");
        int displacement = validateCallbackLoad(body[3]);
        require((displacement & (4 - 1)) == 0,
            "callback displacement is unaligned");
        validatePush(body[4], "EDX");
        validateLoadRegister(body[5], "EDX", "ESP", 0x10L);
        validatePush(body[6], "EDX");
        validateIndirectCall(body[7], "EAX");
        validatePop(body[8], "ESI");
        validateReturn(body[9]);
        return displacement / 4;
    }

    private void validateLoadRegister(Instruction instruction, String target,
                                      String base, long displacement) {
        require("MOV".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 2 &&
                singleRegister(instruction.getOpObjects(0), target),
            "case vtable load shape mismatch");
        require(memoryOperand(instruction.getOpObjects(1), base, displacement),
            "case load operand mismatch");
        require(hasLoadWidth(instruction, 4), "case load width mismatch");
    }

    private void validateAdd(Instruction instruction, String target,
                             long immediate) {
        require("ADD".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 2 &&
                singleRegister(instruction.getOpObjects(0), target),
            "payload adjustment shape mismatch");
        Object[] objects = instruction.getOpObjects(1);
        require(objects.length == 1 && objects[0] instanceof Scalar &&
                ((Scalar) objects[0]).getUnsignedValue() == immediate,
            "payload adjustment value mismatch");
    }

    private int validateCallbackLoad(Instruction instruction) {
        require("MOV".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 2 &&
                singleRegister(instruction.getOpObjects(0), "EAX"),
            "callback load shape mismatch");
        Object[] objects = instruction.getOpObjects(1);
        int registers = 0;
        int scalars = 0;
        long displacement = -1L;
        for (Object object : objects) {
            if (object instanceof Register &&
                    "ESI".equalsIgnoreCase(((Register) object).getName())) {
                registers++;
            }
            else if (object instanceof Scalar) {
                scalars++;
                displacement = ((Scalar) object).getUnsignedValue();
            }
            else {
                throw new IllegalStateException("callback load operand mismatch");
            }
        }
        require(registers == 1 && scalars == 1 && displacement >= 0,
            "callback displacement missing");
        require(hasLoadWidth(instruction, 4), "callback load width mismatch");
        require(displacement <= Integer.MAX_VALUE,
            "callback displacement range mismatch");
        return (int) displacement;
    }

    private void validatePush(Instruction instruction, String register) {
        require("PUSH".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 1 &&
                singleRegister(instruction.getOpObjects(0), register),
            "case push shape mismatch");
    }

    private void validatePop(Instruction instruction, String register) {
        require("POP".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 1 &&
                singleRegister(instruction.getOpObjects(0), register),
            "case pop shape mismatch");
    }

    private void validateIndirectCall(Instruction instruction, String register) {
        require("CALL".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 1 &&
                singleRegister(instruction.getOpObjects(0), register),
            "callback call shape mismatch");
        require(instruction.getFlowType() != null &&
                instruction.getFlowType().isCall(),
            "callback call flow mismatch");
        int indirectCalls = 0;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLIND) {
                indirectCalls++;
            }
        }
        require(indirectCalls == 1, "callback call is not indirect");
    }

    private void validateReturn(Instruction instruction) {
        require("RET".equalsIgnoreCase(instruction.getMnemonicString()) &&
                instruction.getNumOperands() == 1,
            "case return shape mismatch");
        Object[] objects = instruction.getOpObjects(0);
        require(objects.length == 1 && objects[0] instanceof Scalar &&
                ((Scalar) objects[0]).getUnsignedValue() == CASE_RETURN_BYTES,
            "case return size mismatch");
    }

    private Instruction nextContiguous(Instruction previous, Function owner) {
        Instruction next = currentProgram.getListing().getInstructionAfter(
            previous.getAddress());
        require(next != null && owner.getBody().contains(next.getAddress()) &&
                next.getAddress().equals(previous.getMaxAddress().next()),
            "instruction sequence is not contiguous");
        return next;
    }

    private Instruction previousContiguous(Instruction current, Function owner) {
        Instruction previous = currentProgram.getListing()
            .getInstructionBefore(current.getAddress());
        require(previous != null && owner.getBody().contains(previous.getAddress()) &&
                previous.getMaxAddress().next().equals(current.getAddress()),
            "instruction sequence is not contiguous");
        return previous;
    }

    private boolean memoryOperand(Object[] objects, String base,
                                  long expectedDisplacement) {
        int registers = 0;
        int scalars = 0;
        long displacement = Long.MIN_VALUE;
        for (Object object : objects) {
            if (object instanceof Register &&
                    base.equalsIgnoreCase(((Register) object).getName())) {
                registers++;
            }
            else if (object instanceof Scalar) {
                scalars++;
                displacement = ((Scalar) object).getUnsignedValue();
            }
            else {
                return false;
            }
        }
        if (registers != 1) {
            return false;
        }
        if (expectedDisplacement == 0L && scalars == 0) {
            return true;
        }
        return scalars == 1 && displacement == expectedDisplacement;
    }

    private boolean scaledMemoryOperand(Object[] objects, long tableVa) {
        int registers = 0;
        int scale = 0;
        int table = 0;
        for (Object object : objects) {
            if (object instanceof Register &&
                    "ESI".equalsIgnoreCase(((Register) object).getName())) {
                registers++;
            }
            else if (object instanceof Scalar) {
                long value = ((Scalar) object).getUnsignedValue();
                if (value == 4L) {
                    scale++;
                }
                else if (value == tableVa) {
                    table++;
                }
                else {
                    return false;
                }
            }
            else {
                return false;
            }
        }
        return registers == 1 && scale == 1 && table == 1;
    }

    private boolean singleRegister(Object[] objects, String name) {
        return objects.length == 1 && objects[0] instanceof Register &&
            name.equalsIgnoreCase(((Register) objects[0]).getName());
    }

    private boolean hasScalar(Instruction instruction, long value) {
        for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
            for (Object object : instruction.getOpObjects(operand)) {
                if (object instanceof Scalar &&
                        ((Scalar) object).getUnsignedValue() == value) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean hasLoadWidth(Instruction instruction, int width) {
        int loads = 0;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.LOAD) {
                require(operation.getOutput() != null &&
                        operation.getOutput().getSize() == width,
                    "memory load width mismatch");
                loads++;
            }
        }
        return loads == 1;
    }

    private int readUnsignedByte(long value) throws Exception {
        Address address = address(value);
        require(currentProgram.getMemory().contains(address),
            "byte table entry is missing");
        return currentProgram.getMemory().getByte(address) & 0xff;
    }

    private long readUnsignedDword(long value) throws Exception {
        Memory memory = currentProgram.getMemory();
        long result = 0L;
        for (int i = 0; i < 4; i++) {
            Address address = address(value + i);
            require(memory.contains(address), "dword table entry is missing");
            result |= (memory.getByte(address) & 0xffL) << (i * 8);
        }
        return result;
    }

    private Address address(long value) {
        AddressSpace space = currentProgram.getAddressFactory()
            .getDefaultAddressSpace();
        return space.getAddress(value);
    }

    private String buildObservation(long dispatcherVa, int opcode,
                                    long byteTableVa, long dwordTableVa,
                                    RouteObservation observation) {
        StringBuilder json = new StringBuilder(512);
        json.append("{\"byte_table_entry_va\":\"")
            .append(hex(observation.byteTableEntryVa))
            .append("\",\"byte_table_va\":\"")
            .append(hex(byteTableVa))
            .append("\",\"case_index\":")
            .append(observation.caseIndex)
            .append(",\"check_id\":\"")
            .append(CHECK_ID)
            .append("\",\"dispatcher_va\":\"")
            .append(hex(dispatcherVa))
            .append("\",\"dword_table_va\":\"")
            .append(hex(dwordTableVa))
            .append("\",\"input_id\":\"ffxivgame-1.23b\"")
            .append(",\"opcode\":\"")
            .append(opcodeHex(opcode))
            .append("\",\"schema_version\":1")
            .append(",\"vtable_slot\":")
            .append(observation.callbackSlot)
            .append("}\n");
        return json.toString();
    }

    private String hex(long value) {
        return String.format(Locale.ROOT, "0x%08x", value);
    }

    private String opcodeHex(int value) {
        return String.format(Locale.ROOT, "0x%04x", value);
    }

    private void writeAtomically(String outputSource, String json)
            throws IOException {
        Path output = Paths.get(outputSource).toAbsolutePath().normalize();
        Path parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("observation output parent is unavailable");
        }
        if (Files.exists(output)) {
            throw new IOException("observation output already exists");
        }

        Path temporary = Files.createTempFile(parent, ".zone-dispatch-", ".tmp");
        boolean installed = false;
        try {
            Files.write(temporary, json.getBytes(StandardCharsets.US_ASCII),
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            checkNotCancelled();
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE);
            }
            catch (AtomicMoveNotSupportedException exception) {
                throw new IOException("atomic observation output unavailable");
            }
            installed = true;
            try {
                checkNotCancelled();
            }
            catch (RuntimeException exception) {
                Files.deleteIfExists(output);
                installed = false;
                throw exception;
            }
        }
        finally {
            if (!installed) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private void checkNotCancelled() {
        if (monitor.isCancelled()) {
            throw new IllegalStateException("cancelled");
        }
    }

    private static void require(boolean condition, String reason) {
        if (!condition) {
            throw new IllegalStateException(reason);
        }
    }
}
