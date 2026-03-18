"""
programs.py - RISC-V RV32I programs for YACCA fault injection demo.

Each program is built as a list of (addr, word, comment) tuples.
The builder assembles them into a memory dict for the simulator.

────────────────────────────────────────────────────────────────────────────
SCENARIO: Secure Boot Authorization Check
────────────────────────────────────────────────────────────────────────────

A device boots and checks whether the user has a valid authorization token.
  - user_token  = 0      (attacker, UNAUTHORIZED)
  - secret_key  = 0x50   (correct token is 80 decimal)

Normal flow (no fault):
  Block A → Block B → Block D  (token mismatch → DENY)

Fault attack (inter-block CFE):
  Block A → Block C            (skip auth check → GRANT !!)

YACCA protection detects this:
  Block C checks that its predecessor was Block B (code must = B_B = 7).
  After the fault, code = B_A = 5 ≠ 7  →  ERROR HANDLER triggered.

────────────────────────────────────────────────────────────────────────────
CFG (Control Flow Graph):
────────────────────────────────────────────────────────────────────────────

  ┌─────────┐
  │ Block A │  Entry: set token=0, set key=0x50
  └────┬────┘
       │  j block_b
  ┌────▼────┐
  │ Block B │  Auth check: compare token vs key
  └────┬────┘
   BNE │ (token ≠ key)          ┌──────────────┐
  ┌────▼────┐     (token = key) │              │
  │ Block D │◄──────────────────┘   Block C    │← ATTACK TARGET
  │  DENY   │               GRANT─────►Block C │
  └────┬────┘                        └────┬────┘
       │                                  │
       └──────────────────────────────────┘
                        │
                   ┌────▼────┐
                   │ Block E │  HALT (infinite loop / ebreak)
                   └─────────┘

Fault arrow: Block A ──fault──► Block C  (invalid CFG edge)
YACCA check in Block C: code should be B_B=7, but gets B_A=5 → ERROR

────────────────────────────────────────────────────────────────────────────
Register usage:
  t0  (x5)  = user_token
  t1  (x6)  = secret_key
  a0  (x10) = output (read by EBREAK)
  t4  (x29) = YACCA temp
  t5  (x30) = YACCA code register
────────────────────────────────────────────────────────────────────────────
"""

from riscv_sim import (
    enc_addi, enc_xori, enc_lui, enc_jal, enc_bne, enc_beq, enc_ebreak,
    RV32CPU, u32
)

BASE  = 0x80000000  # Reset vector / program start

# Register numbers
T0  = 5   # user_token
T1  = 6   # secret_key
A0  = 10  # output
T4  = 29  # YACCA temp
T5  = 30  # YACCA code register

# Output sentinel values (fit in 12-bit signed → single ADDI instruction)
RESULT_GRANTED =  1    # Access granted  → "SUCCESS (BREACH!)"
RESULT_DENIED  =  0    # Access denied   → "SAFE: access denied"
RESULT_ERROR   = -1    # CFE detected    → "ATTACK STOPPED by YACCA"

# YACCA compile-time signatures (unique random values)
# B_X is the "identity" of block X; M2_X = B_pred_X XOR B_X
CODE_INIT =  1   # initial code value (no predecessor)
B_A       =  5   # Block A signature
B_B       =  7   # Block B signature
B_C       = 11   # Block C (grant) signature
B_D       = 13   # Block D (deny)  signature

M2_A = CODE_INIT ^ B_A   # = 4  (update at end of A)
M2_B = B_A ^ B_B          # = 2  (update at end of B)
M2_C = B_B ^ B_C          # = 12 (update at end of C)
M2_D = B_B ^ B_D          # = 10 (update at end of D)

# ── Helper: assemble address list into memory dict ─────────────────────────

def build_memory(instructions):
    """
    instructions: list of (addr, word, comment)
    Returns: dict {addr: word}
    """
    mem = {}
    for addr, word, _ in instructions:
        mem[addr] = word & 0xFFFFFFFF
    return mem


def show_listing(instructions, title):
    print(f"\n{'═'*68}")
    print(f"  {title}")
    print(f"{'═'*68}")
    for addr, word, comment in instructions:
        print(f"  {addr:08X}: {word:08X}  ; {comment}")
    print()


# ── Utility: offset between two addresses ─────────────────────────────────

def off(from_addr, to_addr):
    """Signed byte offset from_addr → to_addr (for branch/jal)."""
    return (to_addr - from_addr) & 0xFFFFFFFF  # keep as u32 for encoder


# ══════════════════════════════════════════════════════════════════════════════
#  PROGRAM 1: Unprotected (no YACCA)
# ══════════════════════════════════════════════════════════════════════════════
#
# Address map:
#   BASE + 0x00 : block_a_0  addi t0, x0, 0
#   BASE + 0x04 : block_a_1  addi t1, x0, 0x50
#   BASE + 0x08 : block_a_2  j block_b          ← FAULT POINT (instruction index 2)
#   BASE + 0x0C : block_b_0  bne t0, t1, block_d
#   BASE + 0x10 : block_b_1  j block_c
#   BASE + 0x14 : block_c_0  addi a0, x0, 1     (GRANTED)
#   BASE + 0x18 : block_c_1  ebreak
#   BASE + 0x1C : block_d_0  addi a0, x0, 0     (DENIED)
#   BASE + 0x20 : block_d_1  ebreak
#
# Symbols:
NOPROTECT_BLOCK_A   = BASE + 0x00
NOPROTECT_BLOCK_B   = BASE + 0x0C
NOPROTECT_BLOCK_C   = BASE + 0x14   # grant (ATTACK TARGET)
NOPROTECT_BLOCK_D   = BASE + 0x1C   # deny
NOPROTECT_FAULT_PC  = BASE + 0x08   # the j block_b instruction to replace


def make_noprotect():
    """
    Build the unprotected program.
    Returns (instructions_list, memory_dict, symbol_dict).
    """
    a = NOPROTECT_BLOCK_A
    b = NOPROTECT_BLOCK_B
    c = NOPROTECT_BLOCK_C
    d = NOPROTECT_BLOCK_D

    instrs = [
        # ─── Block A: Entry ──────────────────────────────────────────────────
        (a+0x00, enc_addi(T0, 0,  0),         "Block A: t0 = user_token = 0 (unauthorized)"),
        (a+0x04, enc_addi(T1, 0,  0x50),      "Block A: t1 = secret_key = 0x50 (80)"),
        (a+0x08, enc_jal(0, off(a+0x08, b)),  "Block A: j block_b  ← FAULT POINT"),

        # ─── Block B: Authorization Check ────────────────────────────────────
        (b+0x00, enc_bne(T0, T1, off(b+0x00, d)),  "Block B: if t0 != t1 → deny"),
        (b+0x04, enc_jal(0,  off(b+0x04, c)),       "Block B: j block_c (token matched)"),

        # ─── Block C: GRANT (Attack Target) ──────────────────────────────────
        (c+0x00, enc_addi(A0, 0, RESULT_GRANTED),  "Block C: a0 = GRANTED (1)"),
        (c+0x04, enc_ebreak(),                      "Block C: EBREAK → report output"),

        # ─── Block D: DENY ───────────────────────────────────────────────────
        (d+0x00, enc_addi(A0, 0, RESULT_DENIED),   "Block D: a0 = DENIED (0)"),
        (d+0x04, enc_ebreak(),                      "Block D: EBREAK → report output"),
    ]

    mem = build_memory(instrs)
    syms = {
        'block_a': a, 'block_b': b, 'block_c': c, 'block_d': d,
        'fault_pc': NOPROTECT_FAULT_PC,
    }
    return instrs, mem, syms


# ══════════════════════════════════════════════════════════════════════════════
#  PROGRAM 2: YACCA-Protected
# ══════════════════════════════════════════════════════════════════════════════
#
# YACCA_CMP mechanism:
#   • At END   of block X : t5 ^= M2_X   → t5 becomes B_X
#   • At START of block Y : verify t5 == B_pred_Y, else → error_handler
#
# Block A (no predecessor): init t5=CODE_INIT(1), update: t5 ^= M2_A → t5=5=B_A
# Block B (pred=A, expect t5=B_A=5): verify, update: t5 ^= M2_B → t5=7=B_B
# Block C (pred=B, expect t5=B_B=7): verify → if fault (t5=B_A=5≠7) → ERROR!
# Block D (pred=B, expect t5=B_B=7): verify
# Error Handler: a0 = -1, ebreak
#
# Address map (from BASE):
YACCA_BLOCK_A      = BASE + 0x00   # 5 instructions (0x00..0x10)
YACCA_BLOCK_B      = BASE + 0x14   # 5 instructions (0x14..0x24)
YACCA_BLOCK_C      = BASE + 0x28   # 4 instructions (0x28..0x34) ← grant
YACCA_BLOCK_D      = BASE + 0x38   # 4 instructions (0x38..0x44) ← deny
YACCA_ERROR        = BASE + 0x48   # 2 instructions (0x48..0x4C) ← CFE handler
YACCA_FAULT_PC     = BASE + 0x10   # j block_b in Block A  ← FAULT POINT


def make_yacca():
    """
    Build the YACCA-protected program.
    Returns (instructions_list, memory_dict, symbol_dict).
    """
    a = YACCA_BLOCK_A
    b = YACCA_BLOCK_B
    c = YACCA_BLOCK_C
    d = YACCA_BLOCK_D
    e = YACCA_ERROR

    instrs = [
        # ─── Block A: Entry (no predecessor verification) ────────────────────
        (a+0x00, enc_addi(T5, 0, CODE_INIT),    "Block A: t5 = CODE_INIT = 1"),
        (a+0x04, enc_addi(T0, 0, 0),             "Block A: t0 = user_token = 0 (unauthorized)"),
        (a+0x08, enc_addi(T1, 0, 0x50),          "Block A: t1 = secret_key = 0x50"),
        (a+0x0C, enc_xori(T5, T5, M2_A),         f"Block A: t5 ^= {M2_A}  → t5 = B_A = {B_A}"),
        (a+0x10, enc_jal(0, off(a+0x10, b)),     "Block A: j block_b      ← FAULT POINT"),

        # ─── Block B: Auth Check (pred=A, expect t5=B_A=5) ───────────────────
        (b+0x00, enc_addi(T4, 0, B_A),            f"Block B: t4 = B_A = {B_A}"),
        (b+0x04, enc_bne(T5, T4, off(b+0x04, e)), "Block B: if t5 != B_A → error (CFE!)"),
        # Application code + YACCA update BEFORE branch
        (b+0x08, enc_xori(T5, T5, M2_B),          f"Block B: t5 ^= {M2_B}  → t5 = B_B = {B_B}"),
        (b+0x0C, enc_bne(T0, T1, off(b+0x0C, d)), "Block B: if token != key → deny"),
        (b+0x10, enc_jal(0, off(b+0x10, c)),       "Block B: j block_c (token matched)"),

        # ─── Block C: GRANT (pred=B, expect t5=B_B=7) ────────────────────────
        (c+0x00, enc_addi(T4, 0, B_B),             f"Block C: t4 = B_B = {B_B}"),
        (c+0x04, enc_bne(T5, T4, off(c+0x04, e)),  "Block C: if t5 != B_B → error (CFE!)"),
        (c+0x08, enc_addi(A0, 0, RESULT_GRANTED),   "Block C: a0 = GRANTED (1)"),
        (c+0x0C, enc_ebreak(),                       "Block C: EBREAK → report output"),

        # ─── Block D: DENY (pred=B, expect t5=B_B=7) ─────────────────────────
        (d+0x00, enc_addi(T4, 0, B_B),             f"Block D: t4 = B_B = {B_B}"),
        (d+0x04, enc_bne(T5, T4, off(d+0x04, e)),  "Block D: if t5 != B_B → error (CFE!)"),
        (d+0x08, enc_addi(A0, 0, RESULT_DENIED),    "Block D: a0 = DENIED (0)"),
        (d+0x0C, enc_ebreak(),                       "Block D: EBREAK → report output"),

        # ─── Error Handler: CFE detected by YACCA ────────────────────────────
        (e+0x00, enc_addi(A0, 0, RESULT_ERROR),     "ERROR: a0 = -1 (CFE detected)"),
        (e+0x04, enc_ebreak(),                       "ERROR: EBREAK → report"),
    ]

    mem = build_memory(instrs)
    syms = {
        'block_a': a, 'block_b': b, 'block_c': c, 'block_d': d,
        'error': e,   'fault_pc': YACCA_FAULT_PC,
    }
    return instrs, mem, syms


# ── Fault injection ────────────────────────────────────────────────────────

def inject_fault(memory: dict, fault_pc: int, target_pc: int) -> dict:
    """
    Patch memory: replace instruction at fault_pc with JAL x0, (target_pc - fault_pc).
    Returns a new memory dict (original not modified).
    """
    patched = dict(memory)
    replacement = enc_jal(0, off(fault_pc, target_pc))
    patched[fault_pc] = replacement
    return patched


# ── Quick self-test ────────────────────────────────────────────────────────

if __name__ == "__main__":
    i, m, s = make_noprotect()
    show_listing(i, "UNPROTECTED PROGRAM")
    i, m, s = make_yacca()
    show_listing(i, "YACCA-PROTECTED PROGRAM")
