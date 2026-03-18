#!/usr/bin/env python3
"""
run_demo.py  –  YACCA Fault-Injection Demo for biRISC-V
═══════════════════════════════════════════════════════════════════════════════

Demonstrates how a Control Flow Error (CFE / fault attack) can break a
security-critical program, and how YACCA (Yet Another Control-flow Checking
using Assertions) detects and stops the attack.

Reference: Vankeirsbilck, "Advancing Control Flow Error Detection Techniques
           for Embedded Software using Automated Implementation and Fault
           Injection", KU Leuven, 2020 – §2.3.2 YACCA.

Target: biRISC-V (dual-issue RISC-V RV32I, https://github.com/YarosLove91/biriscv)

Usage:
    python3 run_demo.py            # run all 4 experiments
    python3 run_demo.py --trace    # also print instruction trace
    python3 run_demo.py --listing  # print assembly listings
═══════════════════════════════════════════════════════════════════════════════
"""

import sys
import textwrap
from riscv_sim import RV32CPU, disasm
from programs import (
    make_noprotect, make_yacca, inject_fault, show_listing,
    NOPROTECT_BLOCK_A, NOPROTECT_BLOCK_C, NOPROTECT_FAULT_PC,
    YACCA_BLOCK_A,    YACCA_BLOCK_C,    YACCA_FAULT_PC,
    RESULT_GRANTED, RESULT_DENIED, RESULT_ERROR,
    B_A, B_B, CODE_INIT,
)

# ── Colour helpers (ANSI) ─────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

USE_COLOR = sys.stdout.isatty()

def col(text, code):
    return f"{code}{text}{RESET}" if USE_COLOR else text

def box(title, width=70):
    bar = "═" * width
    return f"\n{BOLD}{bar}\n  {title}\n{bar}{RESET}"


# ── Result interpreter ────────────────────────────────────────────────────────

def interpret(output):
    """Return (label, color_code, security_status) for a simulation output."""
    if output is None:
        return "TIMEOUT", YELLOW, "?"
    val = output & 0xFFFFFFFF
    signed = val if val < 0x80000000 else val - 0x100000000
    if signed == RESULT_GRANTED:
        return "ACCESS GRANTED", RED, "BREACH"
    if signed == RESULT_DENIED:
        return "ACCESS DENIED", GREEN, "SAFE"
    if signed == RESULT_ERROR:
        return "CFE DETECTED – ATTACK STOPPED", GREEN, "PROTECTED"
    return f"UNKNOWN (a0=0x{val:08X})", YELLOW, "?"


# ── Single experiment runner ──────────────────────────────────────────────────

def run_experiment(label, memory, pc_start, trace=False):
    """
    Run one simulation. Returns (output_value, step_count, trace_log).
    """
    cpu = RV32CPU(memory, pc_start=pc_start, trace=trace, max_steps=50_000)
    cpu.run()
    return cpu.output, cpu.steps, cpu.trace_log


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    trace   = "--trace"   in sys.argv
    listing = "--listing" in sys.argv
    verbose = "--verbose" in sys.argv or trace

    # ─── Banner ─────────────────────────────────────────────────────────────
    print(box("YACCA FAULT-INJECTION DEMO  ·  biRISC-V / RISC-V RV32I", width=68))
    print(textwrap.dedent(f"""
    Scenario: Device Secure Boot Authorization Check
    ─────────────────────────────────────────────────
    • user_token  = 0x00  (attacker has NO valid token)
    • secret_key  = 0x50  (correct authorization value)

    Normal path  :  Block A → Block B → Block D  (DENY – correct)
    Fault attack :  Block A ──CFE──► Block C      (bypass auth → GRANT!!)

    YACCA assigns compile-time signatures to each basic block:
      CODE_INIT = {CODE_INIT}  (initial value)
      B_A = {B_A}   B_B = {B_B}   B_C = 11  B_D = 13

    At END   of block X : code ^= M2_X  →  code becomes B_X
    At START of block Y : verify code == B_pred_Y  (else → error)

    After fault: code = B_A = {B_A} at entry of Block C
    Block C expects:    code = B_B = {B_B}
    Mismatch detected → YACCA fires error handler!
    """))

    # ─── Build programs ──────────────────────────────────────────────────────
    np_instrs, np_mem, np_syms = make_noprotect()
    ya_instrs, ya_mem, ya_syms = make_yacca()

    if listing:
        show_listing(np_instrs, "UNPROTECTED PROGRAM (auth_noprotect.S)")
        show_listing(ya_instrs, "YACCA-PROTECTED PROGRAM (auth_yacca.S)")

    # Fault-injected memories:
    #   Unprotected fault: replace j block_b → j block_c at NOPROTECT_FAULT_PC
    np_fault_mem = inject_fault(np_mem, NOPROTECT_FAULT_PC, NOPROTECT_BLOCK_C)
    #   YACCA fault:       same structural attack, but YACCA will catch it
    ya_fault_mem = inject_fault(ya_mem, YACCA_FAULT_PC, YACCA_BLOCK_C)

    # Show what the fault injection does
    original_np  = np_mem[NOPROTECT_FAULT_PC]
    faulted_np   = np_fault_mem[NOPROTECT_FAULT_PC]
    original_ya  = ya_mem[YACCA_FAULT_PC]
    faulted_ya   = ya_fault_mem[YACCA_FAULT_PC]

    print(f"  {col('Fault injection (simulates voltage glitch / EM pulse):', CYAN)}")
    print(f"  • Unprotected @ 0x{NOPROTECT_FAULT_PC:08X}: "
          f"{original_np:08X} ({disasm(original_np, NOPROTECT_FAULT_PC)})")
    print(f"       replaced with: {faulted_np:08X} ({disasm(faulted_np, NOPROTECT_FAULT_PC)})")
    print(f"  • YACCA      @ 0x{YACCA_FAULT_PC:08X}: "
          f"{original_ya:08X} ({disasm(original_ya, YACCA_FAULT_PC)})")
    print(f"       replaced with: {faulted_ya:08X} ({disasm(faulted_ya, YACCA_FAULT_PC)})")

    # ─── Run the 4 experiments ───────────────────────────────────────────────
    experiments = [
        ("1", "Unprotected  | No fault",   np_mem,       NOPROTECT_BLOCK_A),
        ("2", "Unprotected  | FAULT",       np_fault_mem, NOPROTECT_BLOCK_A),
        ("3", "YACCA-prot.  | No fault",   ya_mem,       YACCA_BLOCK_A),
        ("4", "YACCA-prot.  | FAULT",       ya_fault_mem, YACCA_BLOCK_A),
    ]

    results = []
    print(f"\n{'─'*68}")
    print(f"  Running simulations …")
    print(f"{'─'*68}")

    for num, label, mem, pc in experiments:
        out, steps, tlog = run_experiment(label, mem, pc, trace=trace)
        text, color, status = interpret(out)

        if trace and tlog:
            print(f"\n  {col(f'Trace – Experiment {num}: {label}', CYAN)}")
            for line in tlog:
                print(line)

        results.append((num, label, out, steps, text, color, status))
        print(f"  [{num}] {label:<35}  →  {col(text, color)}  ({steps} steps)")

    # ─── Summary table ───────────────────────────────────────────────────────
    print(box("RESULTS SUMMARY", width=68))
    print(f"\n  {'#':<3}  {'Configuration':<35}  {'Result':<32}  {'Security'}")
    print(f"  {'─'*3}  {'─'*35}  {'─'*32}  {'─'*10}")
    for num, label, out, steps, text, color, status in results:
        val_str = f"a0={'N/A' if out is None else f'0x{out & 0xFFFFFFFF:08X}'}"
        print(f"  [{num}]  {label:<35}  {col(text, color):<44}  {col(status, color)}")

    # ─── Analysis ────────────────────────────────────────────────────────────
    print(f"\n{col('Analysis:', BOLD)}\n")

    # Experiment 2: attack succeeded on unprotected
    _, _, out2, _, _, _, status2 = results[1]
    # Experiment 4: attack detected on YACCA
    _, _, out4, _, _, _, status4 = results[3]

    ok_attack  = (status2 == "BREACH")
    ok_protect = (status4 == "PROTECTED")

    if ok_attack:
        print(col("  ✓ Fault attack SUCCEEDED on unprotected program:", RED))
        print("    → Attacker reached Block C (grant_access) without valid token.")
        print("    → Program output: ACCESS GRANTED  (security breach!)")
    else:
        print(col("  ✗ Expected fault attack to succeed on unprotected program.", YELLOW))

    print()
    if ok_protect:
        print(col("  ✓ YACCA DETECTED the attack on the protected program:", GREEN))
        print(f"    → Block C verifies: expected code = B_B = {B_B},  got code = B_A = {B_A}")
        print(f"    → Mismatch → error handler → a0 = -1 (CFE detected)")
        print("    → Access was NOT granted. Attack STOPPED.")
    else:
        print(col("  ✗ Expected YACCA to detect the attack.", YELLOW))

    print()
    if ok_attack and ok_protect:
        print(col("  ═══════════════════════════════════════════════════════", GREEN))
        print(col("  DEMO PASSED: YACCA successfully prevents the fault attack!", GREEN))
        print(col("  ═══════════════════════════════════════════════════════", GREEN))
    else:
        print(col("  WARNING: unexpected simulation result – check programs.", YELLOW))

    # ─── YACCA overhead analysis ─────────────────────────────────────────────
    print(f"\n{col('YACCA Overhead Analysis:', BOLD)}\n")
    _, _, _, np_norm_steps, _, _, _ = results[0]
    _, _, _, ya_norm_steps, _, _, _ = results[2]

    np_instrs_count = len([_ for _ in np_instrs])
    ya_instrs_count = len([_ for _ in ya_instrs])

    overhead_steps = ya_norm_steps - np_norm_steps
    overhead_code  = ya_instrs_count - np_instrs_count

    print(f"  Instructions in program (code size overhead):")
    print(f"    Unprotected : {np_instrs_count} instructions")
    print(f"    YACCA-prot. : {ya_instrs_count} instructions")
    print(f"    Overhead    : +{overhead_code} instructions "
          f"({overhead_code / np_instrs_count * 100:.0f}%)")
    print()
    print(f"  Execution steps (execution time overhead):")
    print(f"    Unprotected : {np_norm_steps} steps")
    print(f"    YACCA-prot. : {ya_norm_steps} steps")
    print(f"    Overhead    : +{overhead_steps} steps "
          f"({overhead_steps / np_norm_steps * 100:.0f}%)")

    # ─── CFG + YACCA annotations ─────────────────────────────────────────────
    print(f"\n{col('YACCA Code Annotation (RISC-V assembly):', BOLD)}")
    print(textwrap.dedent(f"""
  block_b:                              ; expects code = B_A = {B_A}
      addi  t4, x0, {B_A}                    ; t4 = B_A
      bne   t5, t4, error_handler       ; code ≠ B_A → CFE detected!
      xori  t5, t5, {B_B ^ B_A}                     ; t5 ^= M2_B → t5 = B_B = {B_B}
      bne   t0, t1, block_d             ; application: if token ≠ key → deny
      j     block_c

  block_c:                              ; expects code = B_B = {B_B}
      addi  t4, x0, {B_B}                    ; t4 = B_B
      bne   t5, t4, error_handler       ; code ≠ B_B → CFE detected!
      ;;; ← fault arrives here with t5 = B_A = {B_A} ≠ {B_B} → DETECTED ✓
      addi  a0, x0, 1                   ; GRANTED
      ebreak
    """))


if __name__ == "__main__":
    main()
