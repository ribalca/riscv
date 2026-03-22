#!/usr/bin/env bash
# setup.sh – Clone biRISC-V and install simulation tools
#
# Usage:
#   chmod +x setup.sh && ./setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIRISCV_DIR="$SCRIPT_DIR/../biriscv"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  YACCA Fault Injection Demo – Environment Setup      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ─── 1. Clone biRISC-V repository ────────────────────────────────────────────
if [ -d "$BIRISCV_DIR" ]; then
    echo "[✓] biRISC-V repo already cloned at: $BIRISCV_DIR"
else
    echo "[→] Cloning biRISC-V (periphery branch)..."
    git clone --branch periphery \
        https://github.com/YarosLove91/biriscv.git \
        "$BIRISCV_DIR"
    echo "[✓] Cloned to $BIRISCV_DIR"
fi

# ─── 2. Check / install tools ────────────────────────────────────────────────
check_tool() {
    if command -v "$1" &>/dev/null; then
        echo "[✓] $1 found: $(which $1)"
        return 0
    else
        echo "[✗] $1 NOT FOUND"
        return 1
    fi
}

echo ""
echo "Checking tools..."
MISSING=0
check_tool /usr/bin/iverilog        || MISSING=1
check_tool riscv32-linux-gnu-gcc || {
    check_tool riscv64-linux-gnu-gcc || MISSING=1
}
check_tool python3         || MISSING=1

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "Install missing tools:"
    echo ""
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  macOS (Homebrew):"
        echo "    brew install icarus-verilog"
        echo "    brew install riscv-gnu-toolchain"
    else
        echo "  Ubuntu/Debian:"
        echo "    sudo apt install iverilog"
        echo "    sudo apt install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu"
        echo "  (Then use CROSS=riscv64-linux-gnu in sw/Makefile)"
    fi
    echo ""
fi

# ─── 3. Copy TCM memory modules to tb/ ───────────────────────────────────────
TB_SRC="$BIRISCV_DIR/tb/tb_core_icarus"
TB_DST="$SCRIPT_DIR/tb"

for f in tcm_mem.v tcm_mem_ram.v; do
    if [ -f "$TB_SRC/$f" ]; then
        cp "$TB_SRC/$f" "$TB_DST/$f"
        echo "[✓] Copied $f → tb/"
    else
        echo "[!] $f not found in biRISC-V repo (check repo structure)"
    fi
done

# ─── 4. Create build directories ─────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/../build/sw" "$SCRIPT_DIR/../build/tb"
echo "[✓] Build directories created"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Setup complete. Next steps:"
echo ""
echo "  # Run Python simulation (no tools needed):"
echo "  cd fault_simulator && python3 run_demo.py"
echo ""
echo "  # Run with assembly listing:"
echo "  python3 run_demo.py --listing"
echo ""
echo "  # Build RISC-V binaries (needs toolchain):"
echo "  cd fault_simulator/sw && make"
echo ""
echo "  # Run RTL simulation on biRISC-V (needs iverilog + toolchain):"
echo "  cd fault_simulator/sw && make"
echo "  cd ../tb && make"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
