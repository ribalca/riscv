# Makefile – biRISC-V YACCA fault injection simulation
#
# Requirements:
#   iverilog   (Icarus Verilog)
#   riscv32-unknown-elf-gcc + riscv32-unknown-elf-nm (for building programs)
#
# Install on macOS:  brew install icarus-verilog riscv-gnu-toolchain
# Install on Ubuntu: apt install iverilog gcc-riscv32-unknown-elf

BIRISCV  ?= ../../biriscv          # path to cloned biRISC-V repo
CORE_DIR  = $(BIRISCV)/src/core
BUILD_SW  = ../build/sw
BUILD_TB  = ../build/tb

IVERILOG  = iverilog
VVP       = vvp
NM        = riscv32-unknown-elf-nm

# Verilog source files
RTL_SRCS  = $(wildcard $(CORE_DIR)/*.v)
TB_SRCS   = tb_fault_inject.v tcm_mem.v tcm_mem_ram.v

# Common iverilog flags
IFLAGS   = -g2001 -DTRACE=1 -Dverilog_sim \
            -I$(CORE_DIR) -I.

all: noprotect_normal noprotect_fault yacca_normal yacca_fault
	@echo ""
	@echo "All 4 simulations complete."

dirs:
	mkdir -p $(BUILD_TB)

# ─── Experiment 1: Unprotected, no fault ─────────────────────────────────────
noprotect_normal: dirs $(BUILD_SW)/auth_noprotect.bin
	$(IVERILOG) $(IFLAGS) \
	  -DTCM_BIN='"$(BUILD_SW)/auth_noprotect.bin"' \
	  -DFAULT_INJECT=0 \
	  -o $(BUILD_TB)/sim_np_norm.vvp \
	  $(TB_SRCS) $(RTL_SRCS)
	@echo "=== [1] Unprotected | No fault ==="
	$(VVP) $(BUILD_TB)/sim_np_norm.vvp

# ─── Experiment 2: Unprotected, WITH fault ───────────────────────────────────
# FAULT: at 0x80000008 replace "j block_b" with "j block_c"
# j block_c = JAL x0, +12  = 0x00C0006F
noprotect_fault: dirs $(BUILD_SW)/auth_noprotect.bin
	$(IVERILOG) $(IFLAGS) \
	  -DTCM_BIN='"$(BUILD_SW)/auth_noprotect.bin"' \
	  -DFAULT_INJECT=1 \
	  -DFAULT_ADDR=32\'h80000008 \
	  -DFAULT_INSTR=32\'h00C0006F \
	  -DFAULT_CYCLE=10 \
	  -o $(BUILD_TB)/sim_np_fault.vvp \
	  $(TB_SRCS) $(RTL_SRCS)
	@echo "=== [2] Unprotected | FAULT INJECTED ==="
	$(VVP) $(BUILD_TB)/sim_np_fault.vvp

# ─── Experiment 3: YACCA-protected, no fault ─────────────────────────────────
yacca_normal: dirs $(BUILD_SW)/auth_yacca.bin
	$(IVERILOG) $(IFLAGS) \
	  -DTCM_BIN='"$(BUILD_SW)/auth_yacca.bin"' \
	  -DFAULT_INJECT=0 \
	  -o $(BUILD_TB)/sim_ya_norm.vvp \
	  $(TB_SRCS) $(RTL_SRCS)
	@echo "=== [3] YACCA-protected | No fault ==="
	$(VVP) $(BUILD_TB)/sim_ya_norm.vvp

# ─── Experiment 4: YACCA-protected, WITH fault ───────────────────────────────
# FAULT: at 0x80000010 replace "j block_b" with "j block_c"
# j block_c = JAL x0, +24  = 0x0180006F
yacca_fault: dirs $(BUILD_SW)/auth_yacca.bin
	$(IVERILOG) $(IFLAGS) \
	  -DTCM_BIN='"$(BUILD_SW)/auth_yacca.bin"' \
	  -DFAULT_INJECT=1 \
	  -DFAULT_ADDR=32\'h80000010 \
	  -DFAULT_INSTR=32\'h0180006F \
	  -DFAULT_CYCLE=10 \
	  -o $(BUILD_TB)/sim_ya_fault.vvp \
	  $(TB_SRCS) $(RTL_SRCS)
	@echo "=== [4] YACCA-protected | FAULT INJECTED ==="
	$(VVP) $(BUILD_TB)/sim_ya_fault.vvp

# ─── Waveforms ────────────────────────────────────────────────────────────────
wave: dirs
	$(IVERILOG) $(IFLAGS) -DDUMP_VCD=1 \
	  -DTCM_BIN='"$(BUILD_SW)/auth_yacca.bin"' \
	  -DFAULT_INJECT=1 -DFAULT_ADDR=32\'h80000010 -DFAULT_INSTR=32\'h0180006F \
	  -o $(BUILD_TB)/sim_wave.vvp $(TB_SRCS) $(RTL_SRCS)
	$(VVP) $(BUILD_TB)/sim_wave.vvp
	gtkwave wave.vcd

# ─── Software build (convenience target) ─────────────────────────────────────
sw:
	$(MAKE) -C ../sw

clean:
	rm -rf $(BUILD_TB)

.PHONY: all dirs noprotect_normal noprotect_fault yacca_normal yacca_fault wave sw clean
