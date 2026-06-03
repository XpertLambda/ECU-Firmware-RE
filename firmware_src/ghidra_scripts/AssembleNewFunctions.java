//@category Assembly
//@runtime Java
//
// Multi-pass TriCore assembler for the rewritten
//   * UDS SecurityAccess Dispatcher (0x80019EC2)
//   * Seed-to-Key primitive       (0x8001B57E)
// Resolves forward labels by iterating until instruction sizes converge.
// Prints the encoded bytes for each function so the firmware build script
// can paste them into _assembled_functions.py.

import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.program.model.address.Address;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class AssembleNewFunctions extends GhidraScript {

    static class Op {
        String text;       // null when this entry is a label-marker
        String label;      // non-null when this entry is a label-marker
        Op(String text, String label) { this.text = text; this.label = label; }
        static Op instr(String s) { return new Op(s, null); }
        static Op marker(String l) { return new Op(null, l); }
    }

    // Final encoded bytes per Op, indexed in source order.
    private byte[][] encoded;
    private Map<String, Long> labelOffset = new LinkedHashMap<>();
    private Assembler asm;
    private Address baseAddr;

    private static final Pattern LABEL_REF = Pattern.compile("\\bLBL_[A-Z0-9_]+\\b");

    private byte[] assembleAll(List<Op> ops, Address start) throws Exception {
        baseAddr = start;
        encoded = new byte[ops.size()][];
        // Initial guess: every instruction is 4 bytes (TriCore worst case);
        // exact widths will refine on successive passes.
        for (int i = 0; i < ops.size(); i++) {
            if (ops.get(i).label != null) encoded[i] = new byte[0];
            else                          encoded[i] = new byte[4];
        }
        for (int pass = 0; pass < 10; pass++) {
            // Pass A: compute label offsets from current encoded sizes.
            labelOffset.clear();
            long off = 0;
            for (int i = 0; i < ops.size(); i++) {
                Op op = ops.get(i);
                if (op.label != null) {
                    labelOffset.put(op.label, off);
                } else {
                    off += encoded[i].length;
                }
            }
            // Pass B: re-encode every instruction with concrete addresses,
            // tracking whether anything changed length this pass.
            off = 0;
            boolean changed = false;
            for (int i = 0; i < ops.size(); i++) {
                Op op = ops.get(i);
                if (op.label != null) continue;
                String src = substituteLabels(op.text, off);
                byte[] nb = asm.assembleLine(start.add(off), src);
                if (nb.length != encoded[i].length) changed = true;
                encoded[i] = nb;
                off += nb.length;
            }
            if (!changed) break;
            if (pass == 9) throw new RuntimeException("assembler did not converge");
        }
        // Concatenate.
        int total = 0;
        for (byte[] b : encoded) total += b.length;
        byte[] out = new byte[total];
        int p = 0;
        for (byte[] b : encoded) { System.arraycopy(b, 0, out, p, b.length); p += b.length; }
        return out;
    }

    private String substituteLabels(String src, long currentOffset) {
        Matcher m = LABEL_REF.matcher(src);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String name = m.group();
            Long lbl = labelOffset.get(name);
            if (lbl == null) {
                // Label not yet known on first pass — point near self so the
                // assembler picks a small encoding, which is its safe default.
                m.appendReplacement(sb,
                    String.format("0x%x", baseAddr.getOffset() + currentOffset));
            } else {
                m.appendReplacement(sb,
                    String.format("0x%x", baseAddr.getOffset() + lbl));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private void emit(String tag, Address start, List<Op> ops) throws Exception {
        byte[] bytes = assembleAll(ops, start);
        println(String.format("=== %s @ 0x%x  (%d bytes) ===", tag,
                              start.getOffset(), bytes.length));
        // Print a Python-tuple-friendly hex dump (16 per line, 0xNN, ...).
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 16 == 0) sb.append("\n");
            sb.append(String.format("0x%02x, ", bytes[i] & 0xff));
        }
        println(sb.toString());
        // Also print resolved label offsets for inspection.
        for (Map.Entry<String,Long> e : labelOffset.entrySet()) {
            println(String.format("  %s = 0x%x (offset 0x%x)",
                e.getKey(), start.getOffset() + e.getValue(), e.getValue()));
        }
    }

    @Override
    public void run() throws Exception {
        asm = Assemblers.getAssembler(currentProgram);

        // -----------------------------------------------------------------
        // 0x80019EC2 — UDS SecurityAccess Dispatcher (parity-first split)
        // -----------------------------------------------------------------
        Address dispAddr = currentProgram.getAddressFactory().getAddress("0x80019EC2");
        List<Op> disp = new ArrayList<>();
        // Setup
        disp.add(Op.instr("lea a3,[a4]0x18"));          // a3 = req + 0x18
        disp.add(Op.instr("mov.aa a2,a4"));             // a2 = req
        disp.add(Op.instr("lea a15,[a5]0x18"));         // a15 = resp + 0x18 (status base)
        disp.add(Op.instr("ld.bu d15,[a3]#0x3"));       // d15 = req[0x1B] = subfunc
        disp.add(Op.instr("extr.u d9,d15,#0x0,#0x8"));  // d9 = subfunc & 0xFF
        // Parity-first split: bit 0 of d15 selects parity.
        disp.add(Op.instr("jz.t d15,#0x0,LBL_EVEN_PATH"));
        // ----- ODD branch -----
        disp.add(Op.instr("mov d4,#0x7f"));
        disp.add(Op.instr("jeq d9,d4,LBL_ODD_SPECIAL"));
        // odd-common: RequestSeed
        disp.add(Op.instr("mov d4,d9"));
        disp.add(Op.instr("lea a4,[a5]0x1c"));          // resp.payload
        disp.add(Op.instr("ld.bu d5,[a3]0x4"));         // d5 = req[0x1C] (session_byte)
        disp.add(Op.instr("call 0x8001b57e"));
        disp.add(Op.instr("mov d8,d2"));
        disp.add(Op.instr("st.b [a15]#0x8,d2"));        // resp+0x20 status_requestseed
        disp.add(Op.instr("mov d15,#0x6"));
        disp.add(Op.instr("j LBL_FINAL"));
        // odd-special: subfunc == 0x7F
        disp.add(Op.marker("LBL_ODD_SPECIAL"));
        disp.add(Op.instr("lea a4,[a5]0x1c"));          // resp.payload, d4 still 0x7F
        disp.add(Op.instr("call 0x8001b6d0"));
        disp.add(Op.instr("mov d8,d2"));
        disp.add(Op.instr("st.b [a15]#0xe,d2"));        // resp+0x26 status_7f
        disp.add(Op.instr("mov d15,#0xc"));
        disp.add(Op.instr("j LBL_FINAL"));
        // ----- EVEN branch -----
        disp.add(Op.marker("LBL_EVEN_PATH"));
        disp.add(Op.instr("mov d4,#0x80"));
        disp.add(Op.instr("jeq d9,d4,LBL_EVEN_SPECIAL"));
        // even-common: SendKey
        disp.add(Op.instr("mov d4,d9"));
        disp.add(Op.instr("lea a4,[a2]0x1c"));          // req.payload
        disp.add(Op.instr("mov d5,#0x0"));
        disp.add(Op.instr("call 0x8001b57e"));
        disp.add(Op.instr("j LBL_EVEN_END"));
        // even-special: subfunc == 0x80
        disp.add(Op.marker("LBL_EVEN_SPECIAL"));
        disp.add(Op.instr("lea a4,[a2]0x1c"));          // req.payload, d4 still 0x80
        disp.add(Op.instr("call 0x8001b6d0"));
        disp.add(Op.marker("LBL_EVEN_END"));
        disp.add(Op.instr("mov d8,d2"));
        disp.add(Op.instr("st.b [a15]#0x4,d2"));        // resp+0x1C status_lo
        disp.add(Op.instr("mov d15,#0x2"));
        // ----- FINAL -----
        disp.add(Op.marker("LBL_FINAL"));
        disp.add(Op.instr("st.b [a15]#0x1,d15"));       // resp+0x19 response_tag
        disp.add(Op.instr("mov d0,#0x34"));
        disp.add(Op.instr("jne d8,d0,LBL_SKIP"));
        disp.add(Op.instr("mov d8,#0x0"));
        disp.add(Op.instr("st.b [a15]#0x3,d9"));        // resp+0x1B subfunc echo
        disp.add(Op.marker("LBL_SKIP"));
        disp.add(Op.instr("call 0x8001971c"));
        disp.add(Op.instr("mov d2,d8"));
        disp.add(Op.instr("ret"));
        emit("UDS_SA_Dispatcher", dispAddr, disp);

        // -----------------------------------------------------------------
        // 0x8001B57E — Seed-to-Key (bit-reversed Fibonacci LFSR)
        // -----------------------------------------------------------------
        Address lfsrAddr = currentProgram.getAddressFactory().getAddress("0x8001B57E");
        List<Op> lf = new ArrayList<>();
        // --- Argument-range guard (unchanged) ---
        lf.add(Op.instr("add d0,d4,#-0x1"));
        lf.add(Op.instr("mov d15,#0x7f"));
        lf.add(Op.instr("jge.u d0,d15,LBL_RANGE_BAD"));
        // --- Parity split ---
        lf.add(Op.instr("and d0,d4,#0x1"));
        lf.add(Op.instr("jeq d0,#0x0,LBL_SENDKEY"));
        // ============================================================
        // RequestSeed (odd subfunc) — bit-reversed Fibonacci LFSR
        // ============================================================
        // 1) timer-nonce scramble: g_rolling_seed ^= poly_tbl[STM_TIM0 & 0x3F]
        lf.add(Op.instr("ld.w d15,0xf0000210"));        // STM_TIM0
        lf.add(Op.instr("and d15,#0x3f"));
        lf.add(Op.instr("lea a2,[a1]-0x7eca"));         // a2 = poly table base
        lf.add(Op.instr("addsc.a a15,a2,d15,#0x2"));    // a15 = &poly[nonce]
        lf.add(Op.instr("ld.w d15,[a15]#0x0"));         // d15 = poly[nonce]
        lf.add(Op.instr("ld.w d1,[a0]-0x56fc"));        // d1 = g_rolling_seed
        lf.add(Op.instr("xor d1,d15"));
        lf.add(Op.instr("st.w [a0]-0x56fc,d1"));        // g_rolling_seed = s

        // 2) Emit seed big-endian to buf BEFORE running the LFSR
        lf.add(Op.instr("st.b [a4]0x3,d1"));            // buf[3] = (byte)s
        lf.add(Op.instr("sh d15,d1,#-0x18"));
        lf.add(Op.instr("st.b [a4]#0x0,d15"));          // buf[0] = (byte)(s>>24)
        lf.add(Op.instr("sh d15,d1,#-0x10"));
        lf.add(Op.instr("st.b [a4]#0x1,d15"));          // buf[1] = (byte)(s>>16)
        lf.add(Op.instr("sh d15,d1,#-0x8"));
        lf.add(Op.instr("st.b [a4]#0x2,d15"));          // buf[2] = (byte)(s>>8)

        // 3) Compute rounds = min(session_byte + 0x23, 0xFF)
        lf.add(Op.instr("add d2,d5,#0x23"));
        lf.add(Op.instr("mov d3,#0xff"));
        lf.add(Op.instr("min.u d2,d2,d3"));

        // 4) Look up the LFSR feedback polynomial:
        //    poly = poly_tbl[((subfunc + 1) >> 1) - 1]
        lf.add(Op.instr("add d0,d4,#0x1"));
        lf.add(Op.instr("sh d0,#-0x1"));
        lf.add(Op.instr("add d4,d0,#-0x1"));
        lf.add(Op.instr("addsc.a a2,a2,d4,#0x2"));      // a2 = &poly[idx]
        lf.add(Op.instr("ld.w d0,[a2]"));               // d0 = poly (Galois form)

        // 5) Bit-reverse d0 (Galois poly) into d4 (== rP, Fibonacci-form poly).
        //    The loop destroys its `in` register, so we copy d0 -> d4 first if
        //    needed; here we instead consume d0 directly into d4.
        lf.add(Op.instr("mov d4,d0"));                  // working copy of poly
        bitReverseLoop(lf, "d4", "d0", "d15", "LBL_BR_POLY");
        lf.add(Op.instr("mov d4,d0"));                  // d4 = rP (final)

        // 6) Bit-reverse the LFSR state d1 (=s) into itself.
        //    d3 holds the bit-reversed result; d1 is consumed.
        bitReverseLoop(lf, "d1", "d3", "d15", "LBL_BR_STATE");

        // 7) Right-shift Fibonacci LFSR loop:
        //      for rounds times:
        //          fb = lsb(state)
        //          state >>= 1
        //          if fb: state ^= rP
        // Modelled on the original loop instruction; d3 already holds the
        // bit-reversed state from step 6, d4 holds rP.
        lf.add(Op.instr("jeq d2,#0x0,LBL_LFSR_DONE"));
        lf.add(Op.instr("add d2,#-0x1"));
        lf.add(Op.instr("mov.a a15,d2"));
        lf.add(Op.marker("LBL_LFSR_BODY"));
        lf.add(Op.instr("and d15,d3,#0x1"));            // d15 = state & 1
        lf.add(Op.instr("sh d3,#-0x1"));                // state >>= 1
        lf.add(Op.instr("rsub d15,d15,#0x0"));          // d15 = -fb  (0 or 0xFFFFFFFF)
        lf.add(Op.instr("and d15,d15,d4"));             // d15 = fb ? rP : 0
        lf.add(Op.instr("xor d3,d15"));                 // state ^= maybe_rP
        lf.add(Op.instr("loop a15,LBL_LFSR_BODY"));
        lf.add(Op.marker("LBL_LFSR_DONE"));

        // 8) Bit-reverse final state d3 back into d3 (= Galois-form key).
        //    Stash d3 in d0 temporarily because the loop destroys its input.
        lf.add(Op.instr("mov d0,d3"));
        bitReverseLoop(lf, "d0", "d3", "d15", "LBL_BR_OUT");

        // 9) Store g_expected_key, set seed-pending flag, return 0x34.
        lf.add(Op.instr("ld.w d15,[a0]-0x55c0"));
        lf.add(Op.instr("or d15,#0x2"));
        lf.add(Op.instr("st.w [a0]-0x581c,d3"));        // g_expected_key
        lf.add(Op.instr("st.w [a0]-0x55c0,d15"));       // g_sec_state_flags |= 0x02
        lf.add(Op.instr("j LBL_OK"));

        // ============================================================
        // SendKey (even subfunc) — unchanged from spec
        // ============================================================
        lf.add(Op.marker("LBL_SENDKEY"));
        lf.add(Op.instr("mov d2,#0x33"));               // default NRC_DENIED
        lf.add(Op.instr("ld.w d15,[a0]-0x55c0"));
        lf.add(Op.instr("jz.t d15,#0x1,LBL_RET_RAW"));  // no seed pending → return d2=0x33
        lf.add(Op.instr("lea a15,[a0]-0x55e0"));
        lf.add(Op.instr("ld.w d15,[a0]-0x55c0"));
        lf.add(Op.instr("andn d15,d15,#0x2"));
        lf.add(Op.instr("st.w [a0]-0x55c0,d15"));
        lf.add(Op.instr("st.b [a15]0x54,d0"));          // g_current_sec_lvl = 0
        lf.add(Op.instr("ld.bu d15,[a4]#0x0"));
        lf.add(Op.instr("sha d3,d15,#0x18"));
        lf.add(Op.instr("ld.bu d0,[a4]0x1"));
        lf.add(Op.instr("sha d0,d0,#0x10"));
        lf.add(Op.instr("ld.bu d15,[a4]#0x2"));
        lf.add(Op.instr("sha d15,d15,#0x8"));
        lf.add(Op.instr("ld.bu d1,[a4]0x3"));
        lf.add(Op.instr("or d3,d0"));
        lf.add(Op.instr("or d3,d15"));
        lf.add(Op.instr("ld.w d15,[a0]-0x581c"));
        lf.add(Op.instr("or d3,d1"));
        lf.add(Op.instr("xor d1,d3,d15"));
        lf.add(Op.instr("extr.u d0,d1,#0x0,#0x10"));
        lf.add(Op.instr("sh d15,d1,#-0x10"));
        lf.add(Op.instr("jne d0,d15,LBL_KEY_BAD"));
        lf.add(Op.instr("and d0,d1,#0xff"));
        lf.add(Op.instr("sh d15,d1,#-0x18"));
        lf.add(Op.instr("jne d0,d15,LBL_KEY_BAD"));
        lf.add(Op.instr("mov d15,#0x80"));
        lf.add(Op.instr("jge.u d0,d15,LBL_KEY_BAD"));
        lf.add(Op.instr("add d15,d1,#0x1"));
        lf.add(Op.instr("st.b [a15]0x54,d15"));         // granted level
        lf.add(Op.instr("j LBL_OK"));
        lf.add(Op.marker("LBL_KEY_BAD"));
        lf.add(Op.instr("mov d2,#0x33"));
        lf.add(Op.instr("ret"));
        // ---------- Common returns ----------
        lf.add(Op.marker("LBL_RANGE_BAD"));
        lf.add(Op.instr("mov d2,#0x91"));
        lf.add(Op.instr("ld.w d15,[a0]-0x55c0"));
        lf.add(Op.instr("andn d15,d15,#0x2"));
        lf.add(Op.instr("st.w [a0]-0x55c0,d15"));
        lf.add(Op.instr("ret"));
        lf.add(Op.marker("LBL_OK"));
        lf.add(Op.instr("mov d2,#0x34"));
        lf.add(Op.marker("LBL_RET_RAW"));
        lf.add(Op.instr("ret"));

        emit("SeedToKey_FibForm", lfsrAddr, lf);
    }

    // Emit a bit-by-bit bit-reverse-32 sequence:
    //    out = bit_reverse_32(in)   using two scratch data registers + one
    //                                scratch address register a15.
    // The loop runs exactly 32 times and uses only short (9-bit) immediates
    // so every encoded instruction fits the TriCore short-form.
    private void bitReverseLoop(List<Op> ops, String in, String out, String tmp,
                                String labelPrefix) {
        String body = labelPrefix + "_BODY";
        // result = 0
        ops.add(Op.instr(String.format("mov %s,#0x0", out)));
        // counter = 31 (loop runs 32 times since 'loop' branches while >=0)
        ops.add(Op.instr(String.format("mov %s,#0x1f", tmp)));
        ops.add(Op.instr(String.format("mov.a a15,%s", tmp)));
        ops.add(Op.marker(body));
        ops.add(Op.instr(String.format("sh %s,#0x1", out)));            // result <<= 1
        ops.add(Op.instr(String.format("and %s,%s,#0x1", tmp, in)));    // tmp = in & 1
        ops.add(Op.instr(String.format("or %s,%s", out, tmp)));         // result |= tmp
        ops.add(Op.instr(String.format("sh %s,#-0x1", in)));            // in >>= 1
        ops.add(Op.instr(String.format("loop a15,%s", body)));
    }
}
