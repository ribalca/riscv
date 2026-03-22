/* tb_fault_inject.v – biRISC-V Testbench with YACCA Fault Injection
 *
 * Extends the standard tb_top.v (from biRISC-V/tb/tb_core_icarus/) with:
 *   1. Configurable fault injection: corrupt one instruction in TCM memory
 *      at a programmable cycle count (simulates voltage glitch / EM pulse).
 *   2. Output monitoring: watches SW writes to RESULT_ADDR and reports
 *      the security outcome (ACCESS GRANTED / DENIED / CFE DETECTED).
 *   3. Automatic termination after EBREAK (simulated via store + infinite loop).
 *
 * ─── Usage ────────────────────────────────────────────────────────────────
 * Build & run with Icarus Verilog (from fault_sim/tb/):
 *
 *   # Normal run (no fault):
 *   iverilog -o sim.vvp -DTCM_BIN='"../build/sw/auth_yacca.bin"' \
 *            -I ../../../biriscv/src/core \
 *            tb_fault_inject.v tcm_mem.v tcm_mem_ram.v ../../../../biriscv/src/core/ \*.v && vvp sim.vvp
 * 	      
 *   # Fault run:
 *   iverilog ... -DFAULT_INJECT=1 \
 *               -DFAULT_ADDR=32'h80000010 \
 *               -DFAULT_INSTR=32'h0180006F ...
 *
 * The Python experiment runner (run_demo.py) computes FAULT_INSTR automatically
 * from symbol addresses in the ELF file.
 *
 * ─── Result codes written to RESULT_ADDR (0x80010000) ────────────────────
 *   0x00000001 = ACCESS GRANTED  (security breach if unexpected)
 *   0x00000000 = ACCESS DENIED   (correct for unauthorized user)
 *   0xFFFFFFFF = CFE DETECTED    (YACCA stopped the attack)
 *
 * ─── Parameters (override with +define+ at iverilog compile time) ─────────
 *   TCM_BIN      : path to binary to load (default: ../build/sw/auth_yacca.bin)
 *   FAULT_INJECT : 1 = inject fault, 0 = normal run
 *   FAULT_ADDR   : byte address of instruction to replace
 *   FAULT_INSTR  : 32-bit replacement instruction word
 *   FAULT_CYCLE  : clock cycle at which to apply the fault (default 10)
 *   SIM_TIMEOUT  : max clock cycles before timeout (default 10000)
 *   RESULT_ADDR  : data address to monitor for output (default 0x80010000)
 * ─────────────────────────────────────────────────────────────────────────
 */

`timescale 1ns/1ns

module tb_fault_inject;

// ─── Simulation parameters ──────────────────────────────────────────────────
`ifndef TCM_BIN
  `define TCM_BIN "../build/sw/auth_yacca.bin"
`endif
`ifndef FAULT_INJECT
  `define FAULT_INJECT 0
`endif
`ifndef FAULT_ADDR
  `define FAULT_ADDR 32'h80000010
`endif
`ifndef FAULT_INSTR
  `define FAULT_INSTR 32'h0180006F
`endif
`ifndef FAULT_CYCLE
  `define FAULT_CYCLE 10
`endif
`ifndef SIM_TIMEOUT
  `define SIM_TIMEOUT 10000
`endif
`ifndef RESULT_ADDR
  `define RESULT_ADDR 32'h80010000
`endif

parameter FAULT_INJECT_P = `FAULT_INJECT;
parameter FAULT_CYCLE_P  = `FAULT_CYCLE;
parameter SIM_TIMEOUT_P  = `SIM_TIMEOUT;
parameter [31:0] FAULT_ADDR_P  = `FAULT_ADDR;
parameter [31:0] FAULT_INSTR_P = `FAULT_INSTR;
parameter [31:0] RESULT_ADDR_P = `RESULT_ADDR;

// ─── Clock & reset ──────────────────────────────────────────────────────────
reg clk = 0;
reg rst = 1;

always #5 clk = ~clk;   // 100 MHz

initial begin
    repeat (5) @(posedge clk);
    rst = 0;
end

// ─── Cycle counter & simulation control ─────────────────────────────────────
integer cycle_count;
integer fault_applied;
integer result_seen;
reg [31:0] result_value;

initial begin
    cycle_count  = 0;
    fault_applied = 0;
    result_seen  = 0;
    result_value = 32'hDEAD_DEAD;
end

// ─── Memory wires ───────────────────────────────────────────────────────────
wire [31:0] mem_i_pc_w;
wire        mem_i_rd_w;
wire        mem_i_flush_w;
wire        mem_i_invalidate_w;
wire [63:0] mem_i_inst_w;
wire        mem_i_valid_w;
wire        mem_i_accept_w;

wire [31:0] mem_d_addr_w;
wire        mem_d_rd_w;
wire [3:0]  mem_d_wr_w;
wire [31:0] mem_d_data_wr_w;
wire [31:0] mem_d_data_rd_w;
wire        mem_d_accept_w;
wire        mem_d_ack_w;
wire        mem_d_error_w;
wire [10:0] mem_d_req_tag_w;
wire [10:0] mem_d_resp_tag_w;
wire        mem_d_cacheable_w;
wire        mem_d_invalidate_w;
wire        mem_d_writeback_w;
wire        mem_d_flush_w;

// ─── DUT: biRISC-V core ─────────────────────────────────────────────────────
riscv_core u_dut
(
    .clk_i(clk),
    .rst_i(rst),
    .reset_vector_i(32'h80000000),
    .intr_i(1'b0),
    .cpu_id_i(32'b0),

    // Instruction memory
    .mem_i_pc_o(mem_i_pc_w),
    .mem_i_rd_o(mem_i_rd_w),
    .mem_i_flush_o(mem_i_flush_w),
    .mem_i_invalidate_o(mem_i_invalidate_w),
    .mem_i_inst_i(mem_i_inst_w),
    .mem_i_valid_i(mem_i_valid_w),
    .mem_i_accept_i(mem_i_accept_w),
    .mem_i_error_i(1'b0),

    // Data memory
    .mem_d_addr_o(mem_d_addr_w),
    .mem_d_rd_o(mem_d_rd_w),
    .mem_d_wr_o(mem_d_wr_w),
    .mem_d_data_wr_o(mem_d_data_wr_w),
    .mem_d_data_rd_i(mem_d_data_rd_w),
    .mem_d_accept_i(mem_d_accept_w),
    .mem_d_ack_i(mem_d_ack_w),
    .mem_d_error_i(mem_d_error_w),
    .mem_d_req_tag_o(mem_d_req_tag_w),
    .mem_d_resp_tag_i(mem_d_resp_tag_w),
    .mem_d_cacheable_o(mem_d_cacheable_w),
    .mem_d_invalidate_o(mem_d_invalidate_w),
    .mem_d_writeback_o(mem_d_writeback_w),
    .mem_d_flush_o(mem_d_flush_w)
);

// ─── TCM memory ─────────────────────────────────────────────────────────────
tcm_mem u_mem
(
    .clk_i(clk),
    .rst_i(rst),

    .mem_i_pc_i(mem_i_pc_w),
    .mem_i_rd_i(mem_i_rd_w),
    .mem_i_flush_i(mem_i_flush_w),
    .mem_i_invalidate_i(mem_i_invalidate_w),
    .mem_i_inst_o(mem_i_inst_w),
    .mem_i_valid_o(mem_i_valid_w),
    .mem_i_accept_o(mem_i_accept_w),
    .mem_i_error_o(),  // Not used

    .mem_d_addr_i(mem_d_addr_w),
    .mem_d_rd_i(mem_d_rd_w),
    .mem_d_wr_i(mem_d_wr_w),
    .mem_d_data_wr_i(mem_d_data_wr_w),
    .mem_d_data_rd_o(mem_d_data_rd_w),
    .mem_d_accept_o(mem_d_accept_w),
    .mem_d_ack_o(mem_d_ack_w),
    .mem_d_error_o(mem_d_error_w),
    .mem_d_req_tag_i(mem_d_req_tag_w),
    .mem_d_resp_tag_o(mem_d_resp_tag_w),
    .mem_d_cacheable_i(mem_d_cacheable_w),
    .mem_d_invalidate_i(mem_d_invalidate_w),
    .mem_d_writeback_i(mem_d_writeback_w),
    .mem_d_flush_i(mem_d_flush_w)
);

// ─── Load TCM binary ─────────────────────────────────────────────────────────
// biRISC-V TCM uses 64-bit words; byte address bits [16:3] select the word.
// We load the raw binary and pack two 32-bit words per 64-bit entry.
integer i, fd;
reg [7:0] byte_buf [0:131071];  // 128 KB byte array

initial begin
    $display("[TB] Loading binary: %s", `TCM_BIN);
    fd = $fopen(`TCM_BIN, "rb");
    if (fd == 0) begin
        $display("[TB] ERROR: cannot open %s", `TCM_BIN);
        $finish;
    end
    i = $fread(byte_buf, fd);
    $fclose(fd);
    $display("[TB] Loaded %0d bytes", i);

    // Pack bytes into 64-bit words (little-endian)
    for (i = 0; i < 16384; i = i + 1) begin
        u_mem.u_ram.ram[i] = {
            byte_buf[i*8+7], byte_buf[i*8+6],
            byte_buf[i*8+5], byte_buf[i*8+4],
            byte_buf[i*8+3], byte_buf[i*8+2],
            byte_buf[i*8+1], byte_buf[i*8+0]
        };
    end
    $display("[TB] TCM initialised.");
end

// ─── Fault injection ─────────────────────────────────────────────────────────
// At FAULT_CYCLE, we overwrite the TCM word containing FAULT_ADDR
// with a new 64-bit word in which the relevant 32-bit half is replaced.
// TCM word index = FAULT_ADDR[16:3], half = FAULT_ADDR[2].
wire [13:0] fault_word_idx = FAULT_ADDR_P[16:3];
wire        fault_half     = FAULT_ADDR_P[2];   // 0=low 32b, 1=high 32b

always @(posedge clk) begin
    cycle_count <= cycle_count + 1;

    // Apply fault at the configured cycle
    if (FAULT_INJECT_P && !fault_applied && cycle_count == FAULT_CYCLE_P) begin
        fault_applied <= 1;
        $display("[TB] *** FAULT INJECTION at cycle %0d ***", cycle_count);
        $display("[TB]     Target addr:   0x%08X  (word %0d, half %0d)",
                 FAULT_ADDR_P, fault_word_idx, fault_half);
        $display("[TB]     Original instr: 0x%08X",
                 fault_half ? u_mem.u_ram.ram[fault_word_idx][63:32]
                            : u_mem.u_ram.ram[fault_word_idx][31:0]);
        $display("[TB]     Fault instr:    0x%08X", FAULT_INSTR_P);

        if (fault_half == 0)
            u_mem.u_ram.ram[fault_word_idx][31:0]  = FAULT_INSTR_P;
        else
            u_mem.u_ram.ram[fault_word_idx][63:32] = FAULT_INSTR_P;
    end
end

// ─── Output monitoring ───────────────────────────────────────────────────────
// Watch for data stores to RESULT_ADDR.
always @(posedge clk) begin
    if (!rst && mem_d_wr_w != 4'b0000 && mem_d_addr_w == RESULT_ADDR_P) begin
        result_value = mem_d_data_wr_w;
        result_seen  = 1;

        $display("");
        $display("[TB] ═══════════════════════════════════════════════");
        $display("[TB]  RESULT WRITE detected at cycle %0d", cycle_count);
        $display("[TB]  Address : 0x%08X", mem_d_addr_w);
        $display("[TB]  Value   : 0x%08X", result_value);

        if (result_value == 32'h00000001)
            $display("[TB]  *** ACCESS GRANTED ***  (SECURITY BREACH if unexpected!)");
        else if (result_value == 32'h00000000)
            $display("[TB]  ACCESS DENIED  (safe - unauthorized user rejected)");
        else if (result_value == 32'hFFFFFFFF)
            $display("[TB]  *** CFE DETECTED – ATTACK STOPPED by YACCA! ***");
        else
            $display("[TB]  Unknown result value");

        if (FAULT_INJECT_P)
            $display("[TB]  Fault was INJECTED at cycle %0d", FAULT_CYCLE_P);
        else
            $display("[TB]  No fault (normal run)");

        $display("[TB] ═══════════════════════════════════════════════");
        $display("");

        // Allow a few more cycles then finish
        repeat (20) @(posedge clk);
        $finish;
    end
end

// ─── Simulation timeout ──────────────────────────────────────────────────────
always @(posedge clk) begin
    if (cycle_count >= SIM_TIMEOUT_P) begin
        $display("[TB] TIMEOUT after %0d cycles (no result seen)", cycle_count);
        $finish;
    end
end

// ─── VCD waveform dump ───────────────────────────────────────────────────────
`ifdef DUMP_VCD
initial begin
    $dumpfile("wave.vcd");
    $dumpvars(0, tb_fault_inject);
end
`endif

endmodule
