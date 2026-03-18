"""
riscv_sim.py - Minimal RISC-V RV32I CPU Simulator

Supports the instruction subset needed for YACCA demo:
  ADDI, XORI, LUI, JAL, BNE, BEQ, EBREAK

Register conventions used in programs:
  x0  = zero  (always 0)
  x5  = t0    (user_token)
  x6  = t1    (secret_key)
  x7  = t2    (result staging)
  x10 = a0    (output / EBREAK report value)
  x29 = t4    (YACCA temp)
  x30 = t5    (YACCA code register)
"""

REGS = {
    'x0':0,  'zero':0,
    'x1':1,  'ra':1,
    'x2':2,  'sp':2,
    'x5':5,  't0':5,
    'x6':6,  't1':6,
    'x7':7,  't2':7,
    'x10':10, 'a0':10,
    'x11':11, 'a1':11,
    'x28':28, 't3':28,
    'x29':29, 't4':29,
    'x30':30, 't5':30,
    'x31':31, 't6':31,
}

REG_NAMES = ['x0','ra','sp','gp','tp','t0','t1','t2',
             's0','s1','a0','a1','a2','a3','a4','a5',
             'a6','a7','s2','s3','s4','s5','s6','s7',
             's8','s9','s10','s11','t3','t4','t5','t6']

def sign_ext(val, bits):
    """Sign-extend val from 'bits' bits to 32-bit integer."""
    if val & (1 << (bits - 1)):
        val -= (1 << bits)
    return val

def u32(val):
    return val & 0xFFFFFFFF

# ── Instruction Encoders ──────────────────────────────────────────────────────

def enc_addi(rd, rs1, imm):
    imm = imm & 0xFFF
    return u32((imm << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x13)

def enc_xori(rd, rs1, imm):
    imm = imm & 0xFFF
    return u32((imm << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x13)

def enc_lui(rd, upper20):
    """upper20: the value to load into bits [31:12]"""
    return u32((upper20 & 0xFFFFF) << 12 | (rd << 7) | 0x37)

def enc_jal(rd, offset):
    """offset: signed byte offset (must be even)"""
    off = u32(offset) & 0x1FFFFF
    imm20    = (off >> 20) & 1
    imm10_1  = (off >> 1)  & 0x3FF
    imm11    = (off >> 11) & 1
    imm19_12 = (off >> 12) & 0xFF
    return u32((imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) |
               (imm19_12 << 12) | (rd << 7) | 0x6F)

def enc_bne(rs1, rs2, offset):
    """BNE: branch if rs1 != rs2"""
    return _enc_branch(rs1, rs2, offset, funct3=0b001)

def enc_beq(rs1, rs2, offset):
    """BEQ: branch if rs1 == rs2"""
    return _enc_branch(rs1, rs2, offset, funct3=0b000)

def _enc_branch(rs1, rs2, offset, funct3):
    off = u32(offset) & 0x1FFF
    imm12   = (off >> 12) & 1
    imm10_5 = (off >> 5)  & 0x3F
    imm4_1  = (off >> 1)  & 0xF
    imm11   = (off >> 11) & 1
    return u32((imm12 << 31) | (imm10_5 << 25) | (rs2 << 20) | (rs1 << 15) |
               (funct3 << 12) | (imm4_1 << 8) | (imm11 << 7) | 0x63)

def enc_ebreak():
    return 0x00100073

# ── Disassembler (for trace output) ──────────────────────────────────────────

def disasm(instr, pc=None):
    """Human-readable disassembly of a 32-bit RISC-V instruction."""
    op = instr & 0x7F
    rd  = (instr >> 7)  & 0x1F
    f3  = (instr >> 12) & 0x7
    rs1 = (instr >> 15) & 0x1F
    rs2 = (instr >> 20) & 0x1F

    def rn(r): return REG_NAMES[r]

    if instr == 0x00100073:
        return "ebreak"

    if op == 0x13:  # I-type (ADDI, XORI, ...)
        imm = sign_ext((instr >> 20) & 0xFFF, 12)
        ops = {0: 'addi', 4: 'xori', 6: 'ori', 7: 'andi'}
        mn = ops.get(f3, f'i-op[{f3}]')
        return f"{mn} {rn(rd)}, {rn(rs1)}, {imm}"

    if op == 0x37:  # LUI
        imm = (instr >> 12) & 0xFFFFF
        return f"lui {rn(rd)}, 0x{imm:05X}"

    if op == 0x6F:  # JAL
        # Reconstruct signed offset
        imm20    = (instr >> 31) & 1
        imm10_1  = (instr >> 21) & 0x3FF
        imm11    = (instr >> 20) & 1
        imm19_12 = (instr >> 12) & 0xFF
        off = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1)
        off = sign_ext(off, 21)
        tgt = f"0x{(pc + off) & 0xFFFFFFFF:08X}" if pc is not None else f"{off:+d}"
        if rd == 0:
            return f"j {tgt}"
        return f"jal {rn(rd)}, {tgt}"

    if op == 0x63:  # BRANCH
        imm12   = (instr >> 31) & 1
        imm10_5 = (instr >> 25) & 0x3F
        imm4_1  = (instr >> 8)  & 0xF
        imm11   = (instr >> 7)  & 1
        off = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1)
        off = sign_ext(off, 13)
        tgt = f"0x{(pc + off) & 0xFFFFFFFF:08X}" if pc is not None else f"{off:+d}"
        mnemonics = {0: 'beq', 1: 'bne', 4: 'blt', 5: 'bge', 6: 'bltu', 7: 'bgeu'}
        mn = mnemonics.get(f3, f'br[{f3}]')
        return f"{mn} {rn(rs1)}, {rn(rs2)}, {tgt}"

    return f"<unknown 0x{instr:08X}>"

# ── CPU Simulator ─────────────────────────────────────────────────────────────

class RV32CPU:
    """
    Minimal RISC-V RV32I CPU simulator.

    Memory is a dict: addr -> 32-bit word (word-aligned access).
    Special address OUTPUT_PORT: writes here are treated as program output.
    """
    OUTPUT_PORT = 0xF0000000

    def __init__(self, memory: dict, pc_start: int = 0x80000000,
                 trace: bool = False, max_steps: int = 10_000):
        self.regs  = [0] * 32
        self.pc    = pc_start
        self.mem   = dict(memory)   # copy
        self.trace = trace
        self.max_steps = max_steps

        # Outputs / status
        self.output    = None       # value from last EBREAK (a0)
        self.halted    = False
        self.steps     = 0
        self.trace_log = []         # list of (pc, instr_str) tuples
        self.cfe_detected = False

    # ── Memory access ──────────────────────────────────────────────────────

    def rw(self, addr):
        """Read 32-bit word (word-aligned)."""
        return self.mem.get(addr & 0xFFFFFFFC, 0)

    def ww(self, addr, val):
        """Write 32-bit word."""
        addr &= 0xFFFFFFFC
        val  &= 0xFFFFFFFF
        if addr == self.OUTPUT_PORT:
            self.output = val
        else:
            self.mem[addr] = val

    # ── Register access ────────────────────────────────────────────────────

    def r(self, idx):
        return self.regs[idx] if idx != 0 else 0

    def w(self, idx, val):
        if idx != 0:
            self.regs[idx] = val & 0xFFFFFFFF

    # ── Execution ──────────────────────────────────────────────────────────

    def run(self):
        """Run until EBREAK or max_steps."""
        while not self.halted and self.steps < self.max_steps:
            self.step()
        if not self.halted:
            self.output = None  # Timeout

    def step(self):
        instr = self.rw(self.pc)
        if self.trace:
            dis = disasm(instr, self.pc)
            entry = f"  [{self.pc:08X}] {instr:08X}  {dis}"
            self.trace_log.append(entry)

        self.steps += 1
        self._execute(instr)

    def _execute(self, instr):
        op  = instr & 0x7F
        rd  = (instr >> 7)  & 0x1F
        f3  = (instr >> 12) & 0x7
        rs1 = (instr >> 15) & 0x1F
        rs2 = (instr >> 20) & 0x1F

        # ── EBREAK ────────────────────────────────────────────────────────
        if instr == 0x00100073:
            self.output  = self.r(10)   # a0
            self.halted  = True
            return

        # ── I-type: ADDI / XORI / ORI / ANDI / ... ───────────────────────
        if op == 0x13:
            imm = sign_ext((instr >> 20) & 0xFFF, 12)
            if   f3 == 0: self.w(rd, self.r(rs1) + imm)          # ADDI
            elif f3 == 4: self.w(rd, self.r(rs1) ^ imm)          # XORI
            elif f3 == 6: self.w(rd, self.r(rs1) | imm)          # ORI
            elif f3 == 7: self.w(rd, self.r(rs1) & imm)          # ANDI
            elif f3 == 1: self.w(rd, self.r(rs1) << (imm & 0x1F))  # SLLI
            elif f3 == 5:                                          # SRLI/SRAI
                shamt = imm & 0x1F
                if (imm >> 5) & 0x7F == 0x20:  # SRAI
                    val = sign_ext(self.r(rs1), 32) >> shamt
                    self.w(rd, val)
                else:  # SRLI
                    self.w(rd, self.r(rs1) >> shamt)
            self.pc += 4
            return

        # ── LUI ───────────────────────────────────────────────────────────
        if op == 0x37:
            self.w(rd, instr & 0xFFFFF000)
            self.pc += 4
            return

        # ── AUIPC ─────────────────────────────────────────────────────────
        if op == 0x17:
            self.w(rd, u32(self.pc + (instr & 0xFFFFF000)))
            self.pc += 4
            return

        # ── JAL ───────────────────────────────────────────────────────────
        if op == 0x6F:
            imm20    = (instr >> 31) & 1
            imm10_1  = (instr >> 21) & 0x3FF
            imm11    = (instr >> 20) & 1
            imm19_12 = (instr >> 12) & 0xFF
            off = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1)
            off = sign_ext(off, 21)
            self.w(rd, u32(self.pc + 4))
            self.pc = u32(self.pc + off)
            return

        # ── BRANCH ────────────────────────────────────────────────────────
        if op == 0x63:
            imm12   = (instr >> 31) & 1
            imm10_5 = (instr >> 25) & 0x3F
            imm4_1  = (instr >> 8)  & 0xF
            imm11   = (instr >> 7)  & 1
            off = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1)
            off = sign_ext(off, 13)

            v1, v2 = self.r(rs1), self.r(rs2)
            taken = False
            if   f3 == 0: taken = (v1 == v2)           # BEQ
            elif f3 == 1: taken = (v1 != v2)           # BNE
            elif f3 == 4: taken = (sign_ext(v1,32) < sign_ext(v2,32))  # BLT
            elif f3 == 5: taken = (sign_ext(v1,32) >= sign_ext(v2,32)) # BGE
            elif f3 == 6: taken = (v1 < v2)            # BLTU
            elif f3 == 7: taken = (v1 >= v2)           # BGEU

            self.pc = u32(self.pc + off) if taken else u32(self.pc + 4)
            return

        # ── STORE ─────────────────────────────────────────────────────────
        if op == 0x23:
            imm = sign_ext(((instr >> 25) << 5) | ((instr >> 7) & 0x1F), 12)
            addr = u32(self.r(rs1) + imm)
            self.ww(addr, self.r(rs2))
            self.pc += 4
            return

        # ── LOAD ──────────────────────────────────────────────────────────
        if op == 0x03:
            imm  = sign_ext((instr >> 20) & 0xFFF, 12)
            addr = u32(self.r(rs1) + imm)
            val  = self.rw(addr)
            if   f3 == 0: val = sign_ext(val & 0xFF, 8)    # LB
            elif f3 == 1: val = sign_ext(val & 0xFFFF, 16) # LH
            elif f3 == 2: pass                              # LW
            elif f3 == 4: val = val & 0xFF                 # LBU
            elif f3 == 5: val = val & 0xFFFF               # LHU
            self.w(rd, val)
            self.pc += 4
            return

        # ── R-type ────────────────────────────────────────────────────────
        if op == 0x33:
            f7 = (instr >> 25) & 0x7F
            v1, v2 = self.r(rs1), self.r(rs2)
            if   f3 == 0 and f7 == 0:  self.w(rd, v1 + v2)   # ADD
            elif f3 == 0 and f7 == 0x20: self.w(rd, v1 - v2) # SUB
            elif f3 == 4: self.w(rd, v1 ^ v2)                 # XOR
            elif f3 == 6: self.w(rd, v1 | v2)                 # OR
            elif f3 == 7: self.w(rd, v1 & v2)                 # AND
            self.pc += 4
            return

        # Unknown / unimplemented
        raise RuntimeError(f"Unimplemented instruction 0x{instr:08X} at PC=0x{self.pc:08X}")
