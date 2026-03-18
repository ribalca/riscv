# Makefile – Build RISC-V programs for biRISC-V YACCA demo
#
# Requirements:
#   riscv32-unknown-elf-gcc (or riscv64-unknown-elf-gcc -march=rv32i -mabi=ilp32)
#   riscv32-unknown-elf-objcopy
#   riscv32-unknown-elf-nm
#   riscv32-unknown-elf-objdump
#
# Install on macOS:   brew install riscv-gnu-toolchain
# Install on Ubuntu:  apt install gcc-riscv64-linux-gnu  (use riscv64-linux-gnu-gcc)

CROSS   ?= riscv32-unknown-elf
CC       = $(CROSS)-gcc
OBJCOPY  = $(CROSS)-objcopy
NM       = $(CROSS)-nm
OBJDUMP  = $(CROSS)-objdump

CFLAGS   = -march=rv32i -mabi=ilp32 -nostdlib -nostartfiles -O0
LDFLAGS  = -T link.ld

BUILD    = ../build/sw
STARTUP  = startup.S

all: dirs $(BUILD)/auth_noprotect.bin $(BUILD)/auth_yacca.bin

dirs:
	mkdir -p $(BUILD)

# ─── Unprotected program ──────────────────────────────────────────────────────
$(BUILD)/auth_noprotect.elf: $(STARTUP) auth_noprotect.S link.ld
	$(CC) $(CFLAGS) $(LDFLAGS) $< auth_noprotect.S -o $@

$(BUILD)/auth_noprotect.bin: $(BUILD)/auth_noprotect.elf
	$(OBJCOPY) -O binary $< $@
	@echo "Symbols (unprotected):"
	@$(NM) $< | grep -E 'block_|main|fault'

# ─── YACCA-protected program ──────────────────────────────────────────────────
$(BUILD)/auth_yacca.elf: $(STARTUP) auth_yacca.S link.ld
	$(CC) $(CFLAGS) $(LDFLAGS) $< auth_yacca.S -o $@

$(BUILD)/auth_yacca.bin: $(BUILD)/auth_yacca.elf
	$(OBJCOPY) -O binary $< $@
	@echo "Symbols (YACCA):"
	@$(NM) $< | grep -E 'block_|main|error|fault'

# ─── Disassembly (for inspection) ─────────────────────────────────────────────
disasm: $(BUILD)/auth_noprotect.elf $(BUILD)/auth_yacca.elf
	@echo "=== UNPROTECTED ==="
	$(OBJDUMP) -d $(BUILD)/auth_noprotect.elf
	@echo ""
	@echo "=== YACCA-PROTECTED ==="
	$(OBJDUMP) -d $(BUILD)/auth_yacca.elf

# ─── TCM binaries (for biRISC-V testbench) ───────────────────────────────────
# The testbench reads ./build/tcm.bin; we provide the raw .bin directly.
# Optionally pad to 128KB.
tcm: $(BUILD)/auth_noprotect.bin $(BUILD)/auth_yacca.bin
	dd if=/dev/zero bs=1024 count=128 of=$(BUILD)/tcm_noprotect.bin 2>/dev/null
	dd if=$(BUILD)/auth_noprotect.bin of=$(BUILD)/tcm_noprotect.bin conv=notrunc 2>/dev/null
	dd if=/dev/zero bs=1024 count=128 of=$(BUILD)/tcm_yacca.bin 2>/dev/null
	dd if=$(BUILD)/auth_yacca.bin of=$(BUILD)/tcm_yacca.bin conv=notrunc 2>/dev/null
	@echo "TCM images written to $(BUILD)/"

clean:
	rm -rf $(BUILD)

.PHONY: all dirs disasm tcm clean
