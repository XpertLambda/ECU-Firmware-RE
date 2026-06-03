//@category Validation
//@runtime Java
//
// Java port of PHASE::TEST/keygen_oracle.py.
// Drives FUN_8001B57E in Ghidra's emulator with the rebuilt-binary bytes
// (bit-reversed Fibonacci LFSR formulation) over a sweep of
// (subfunc, saved_state) pairs and dumps (seed, expected_key) tuples to
// /tmp/keygen_oracle_trials.json so run_validation.py can cross-check the
// new synthetic_keygen.py.

import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class KeygenOracle extends GhidraScript {

    // Calling convention / memory layout (mirrors keygen_oracle.py)
    static final long FUN_LFSR        = 0x8001B57EL;
    static final long SENTINEL        = 0xDEADBEEEL;       // return-PC halt
    static final long A1_VAL          = 0x8002DA38L;       // poly-table base anchor
    static final long A0_VAL          = 0xD000C000L;       // small-data base
    static final long EXPECTED_KEY_AD = A0_VAL - 0x581cL;  // g_expected_key
    static final long SAVED_STATE_AD  = A0_VAL - 0x56fcL;  // g_rolling_seed
    static final long STATE_FLAG_AD   = A0_VAL - 0x55c0L;  // g_sec_state_flags
    static final long SEED_BUF        = 0xD0008000L;
    static final long STACK_TOP       = 0xD000B000L;
    static final long STM_TIM0        = 0xF0000210L;

    private AddressSpace defaultSpace;

    private Address A(long off) {
        return defaultSpace.getAddress(off & 0xFFFFFFFFL);
    }

    private void writeU32LE(EmulatorHelper emu, long off, long value) throws Exception {
        byte[] b = new byte[4];
        b[0] = (byte) (value & 0xFF);
        b[1] = (byte) ((value >> 8) & 0xFF);
        b[2] = (byte) ((value >> 16) & 0xFF);
        b[3] = (byte) ((value >> 24) & 0xFF);
        emu.writeMemory(A(off), b);
    }

    private long readU32LE(EmulatorHelper emu, long off) throws Exception {
        byte[] raw = emu.readMemory(A(off), 4);
        return ((raw[0] & 0xFFL))
             | ((raw[1] & 0xFFL) << 8)
             | ((raw[2] & 0xFFL) << 16)
             | ((raw[3] & 0xFFL) << 24);
    }

    private byte[] readBytes(EmulatorHelper emu, long off, int n) throws Exception {
        byte[] raw = emu.readMemory(A(off), n);
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = (byte) (raw[i] & 0xFF);
        return out;
    }

    private long toUint(BigInteger v) {
        return v.longValue() & 0xFFFFFFFFL;
    }

    static class Trial {
        int    subfunc;
        long   timer;
        long   savedState;
        long   retCode;
        byte[] seedBytes;
        long   expectedKey;
        long   stateFlag;
        long   steps;
        String error;
    }

    private Trial runTrial(EmulatorHelper emu, int subfunc, long timerVal,
                           long savedState, long loopModifier) throws Exception {
        Trial t = new Trial();
        t.subfunc = subfunc;
        t.timer = timerVal;
        t.savedState = savedState;

        emu.writeRegister("a0",  BigInteger.valueOf(A0_VAL));
        emu.writeRegister("a1",  BigInteger.valueOf(A1_VAL));
        emu.writeRegister("a4",  BigInteger.valueOf(SEED_BUF));
        emu.writeRegister("a10", BigInteger.valueOf(STACK_TOP));
        emu.writeRegister("a11", BigInteger.valueOf(SENTINEL));
        emu.writeRegister("d4",  BigInteger.valueOf(subfunc));
        emu.writeRegister("d5",  BigInteger.valueOf(loopModifier));
        emu.writeRegister("pc",  BigInteger.valueOf(FUN_LFSR));

        writeU32LE(emu, SAVED_STATE_AD,  savedState);
        writeU32LE(emu, EXPECTED_KEY_AD, 0);
        writeU32LE(emu, STATE_FLAG_AD,   0);
        writeU32LE(emu, SEED_BUF,        0);
        writeU32LE(emu, STM_TIM0,        timerVal);

        long steps = 0;
        final long MAX_STEPS = 200000;
        while (steps < MAX_STEPS) {
            long pc = toUint(emu.readRegister("pc"));
            if (pc == (SENTINEL & 0xFFFFFFFFL)) break;
            if (!emu.step(monitor)) {
                t.error = String.format("step fault @ 0x%08x: %s",
                                        pc, emu.getLastError());
                break;
            }
            steps++;
        }
        if (steps >= MAX_STEPS) t.error = "max steps exhausted";

        t.retCode     = toUint(emu.readRegister("d2")) & 0xFF;
        t.seedBytes   = readBytes(emu, SEED_BUF, 4);
        t.expectedKey = readU32LE(emu, EXPECTED_KEY_AD);
        t.stateFlag   = readU32LE(emu, STATE_FLAG_AD);
        t.steps       = steps;
        return t;
    }

    private String hexBytes(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x & 0xFF));
        return sb.toString();
    }

    private void writeJson(List<Trial> trials, String path) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(path))) {
            pw.println("[");
            for (int i = 0; i < trials.size(); i++) {
                Trial t = trials.get(i);
                pw.println("  {");
                pw.printf("    \"subfunc\": \"0x%02X\",%n", t.subfunc);
                pw.printf("    \"subfunc_int\": %d,%n", t.subfunc);
                pw.printf("    \"loop_modifier\": 0,%n");
                pw.printf("    \"timer\": \"0x%08X\",%n", t.timer);
                pw.printf("    \"saved_state\": \"0x%08X\",%n", t.savedState);
                pw.printf("    \"ret_code\": \"0x%02X\",%n", t.retCode);
                pw.printf("    \"seed_hex\": \"%s\",%n", hexBytes(t.seedBytes));
                long seedBe = ((t.seedBytes[0] & 0xFFL) << 24)
                            | ((t.seedBytes[1] & 0xFFL) << 16)
                            | ((t.seedBytes[2] & 0xFFL) << 8)
                            |  (t.seedBytes[3] & 0xFFL);
                pw.printf("    \"seed_be_u32\": \"0x%08X\",%n", seedBe);
                pw.printf("    \"expected_key\": \"0x%08X\",%n", t.expectedKey);
                pw.printf("    \"state_flag\": \"0x%08X\",%n", t.stateFlag);
                pw.printf("    \"steps\": %d,%n", t.steps);
                pw.printf("    \"error\": \"%s\"%n", t.error == null ? "" : t.error);
                pw.print("  }");
                if (i < trials.size() - 1) pw.println(",");
                else pw.println();
            }
            pw.println("]");
        }
    }

    @Override
    public void run() throws Exception {
        defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        List<Trial> trials = new ArrayList<>();
        try {
            int[] subfuncs = {0x01, 0x03, 0x05, 0x07, 0x09, 0x0B};
            long timerVal = 0;
            long POLY0 = 0xA218B900L;
            long[] seedsViaSavedState = {
                0x00000000L, 0x00000001L, 0xFFFFFFFFL, 0x80000000L,
                0x12345678L, 0xDEADBEEFL, 0xCAFEBABEL, 0xA5A5A5A5L,
                0x5A5A5A5AL, 0xAAAAAAAAL, 0x55555555L, 0x01010101L,
                0x10101010L, 0x7FFFFFFFL, 0x00000002L, 0x00000003L,
                0xA218B900L, 0x8F04FB9DL, 0xF0529CFBL, 0xAF83B3F7L,
                0x98C02CAFL, 0xE0E0B04AL, 0xFF00FF00L, 0x00FF00FFL,
                0x0F0F0F0FL, 0xF0F0F0F0L, 0xDEADC0DEL, 0xFACEFEEDL,
                0xBADC0FFEL, 0x8BADF00DL,
            };
            for (int sf : subfuncs) {
                for (long s : seedsViaSavedState) {
                    long ss = (s ^ POLY0) & 0xFFFFFFFFL;
                    Trial t = runTrial(emu, sf, timerVal, ss, 0);
                    trials.add(t);
                }
            }
        } finally {
            emu.dispose();
        }
        String outPath = "/tmp/keygen_oracle_trials.json";
        writeJson(trials, outPath);
        println(String.format("wrote %d trials -> %s", trials.size(), outPath));
        int ok = 0, faults = 0;
        for (Trial t : trials) {
            if (t.error != null && !t.error.isEmpty()) faults++;
            else ok++;
        }
        println(String.format("ran clean: %d   faulted: %d", ok, faults));
    }
}
