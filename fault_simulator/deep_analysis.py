#!/usr/bin/env python3
"""
deep_analysis.py — Детальный анализ каждого CFE-события:
  - какой бит, в какой инструкции, какой эффект
  - почему YACCA не детектирует 65% (12 BENIGN + 0 missed из 20 CFE)
  - семантика bit-flip'ов по типам инструкций
"""
import sys
sys.path.insert(0, '.')
 
from riscv_sim import RV32CPU, disasm, u32, sign_ext
from programs import (
    make_noprotect, make_yacca,
    NOPROTECT_BLOCK_A, NOPROTECT_BLOCK_B, NOPROTECT_BLOCK_C, NOPROTECT_BLOCK_D,
    YACCA_BLOCK_A, YACCA_BLOCK_B, YACCA_BLOCK_C, YACCA_BLOCK_D, YACCA_ERROR,
    RESULT_GRANTED, RESULT_DENIED, RESULT_ERROR,
    B_A, B_B,
)
from fault_campaign import run_one, inject_bitflip, CFE, BENIGN, DETECTED, CRASH
 
BASE = 0x80000000
 
def classify_out(out):
    if out is None: return CRASH
    s = out if out < 0x80000000 else out - 0x100000000
    if s == RESULT_DENIED:  return BENIGN
    if s == RESULT_GRANTED: return CFE
    if s == RESULT_ERROR:   return DETECTED
    return CRASH
 
# ─── Find all CFE-causing bit-flips in noprotect ─────────────────────────────
 
def find_cfe_bitflips(memory, pc_start, addrs):
    """Вернуть список (addr, bit, orig_instr, faulted_instr, trace) для CFE."""
    results = []
    for addr in addrs:
        orig = memory.get(addr, 0)
        for bit in range(32):
            faulted = u32(orig ^ (1 << bit))
            patched = inject_bitflip(memory, addr, bit)
            try:
                cpu = RV32CPU(patched, pc_start=pc_start, trace=True, max_steps=200)
                cpu.run()
                out = cpu.output
            except RuntimeError:
                out = None
            outcome = classify_out(out)
            if outcome == CFE:
                results.append({
                    'addr':    addr,
                    'bit':     bit,
                    'orig':    orig,
                    'faulted': faulted,
                    'orig_dis':    disasm(orig, addr),
                    'faulted_dis': disasm(faulted, addr),
                    'trace':   cpu.trace_log,
                    'steps':   cpu.steps,
                })
    return results
 
# ─── Cross-check: same semantic fault in YACCA (by original instr content) ───
 
def find_semantic_addr(ya_mem, orig_word):
    """Найти адрес в YACCA-программе, где хранится то же машинное слово."""
    for a, w in ya_mem.items():
        if w == orig_word:
            return a
    return None
 
# ─── Instruction type classifier ─────────────────────────────────────────────
 
def instr_type(word):
    op = word & 0x7F
    tbl = {
        0x13: 'I-type (ADDI/XORI/...)',
        0x37: 'U-type (LUI)',
        0x6F: 'J-type (JAL)',
        0x63: 'B-type (BEQ/BNE/...)',
        0x33: 'R-type (ADD/XOR/...)',
        0x03: 'I-type (LOAD)',
        0x23: 'S-type (STORE)',
        0x73: 'SYSTEM (EBREAK)',
    }
    return tbl.get(op, f'unknown(0x{op:02X})')
 
# ─── Explain why a bit-flip causes CFE ───────────────────────────────────────
 
def explain_cfe(entry):
    addr, bit = entry['addr'], entry['bit']
    orig, faulted = entry['orig'], entry['faulted']
    lines = [
        f"  Адрес       : 0x{addr:08X}  бит {bit}",
        f"  Оригинал    : 0x{orig:08X}  →  {disasm(orig, addr)}",
        f"  С bit-flip  : 0x{faulted:08X}  →  {disasm(faulted, addr)}",
        f"  Тип инструкции: {instr_type(orig)}",
    ]
    # Проанализировать бит в контексте полей инструкции
    op = orig & 0x7F
    if op == 0x13:  # I-type
        field_bit = bit
        if 0 <= field_bit <= 6:    loc = f"opcode[{bit}]"
        elif 7 <= field_bit <= 11: loc = f"rd[{bit-7}]"
        elif 12 <= field_bit <= 14:loc = f"funct3[{bit-12}]"
        elif 15 <= field_bit <= 19:loc = f"rs1[{bit-15}]"
        else:                      loc = f"imm[{bit-20}]"
        lines.append(f"  Поле        : {loc}")
    elif op == 0x6F:  # JAL
        if bit == 31: loc = "imm[20] (знаковый)"
        elif 21 <= bit <= 30: loc = f"imm[{bit-21+1}] (биты 10:1)"
        elif bit == 20: loc = "imm[11]"
        elif 12 <= bit <= 19: loc = f"imm[{bit-12+12}] (биты 19:12)"
        elif 7 <= bit <= 11: loc = f"rd[{bit-7}]"
        else: loc = f"opcode[{bit}]"
        lines.append(f"  Поле JAL    : {loc} — смещение перехода изменено")
    elif op == 0x63:  # BRANCH
        if bit >= 25 and bit <= 30: loc = f"imm/funct3 — изменено смещение/тип ветвления"
        elif 20 <= bit <= 24: loc = f"rs2[{bit-20}]"
        elif 15 <= bit <= 19: loc = f"rs1[{bit-15}]"
        elif 12 <= bit <= 14: loc = f"funct3[{bit-12}] — изменён тип ветвления!"
        else: loc = f"imm/opcode"
        lines.append(f"  Поле BRANCH : {loc}")
 
    lines.append(f"  Шагов       : {entry['steps']}")
    lines.append("  Трасса:")
    for l in entry['trace']:
        lines.append("    " + l.strip())
    return "\n".join(lines)
 
# ─── Main analysis ────────────────────────────────────────────────────────────
 
def main():
    _, np_mem, _ = make_noprotect()
    _, ya_mem, _ = make_yacca()
    np_addrs = sorted(np_mem.keys())
    ya_addrs = sorted(ya_mem.keys())
 
    print("="*68)
    print("  ГЛУБОКИЙ АНАЛИЗ CFE-СОБЫТИЙ")
    print("="*68)
 
    # 1. Найти все CFE в незащищённой версии
    print("\n[1] Поиск всех CFE в незащищённой программе...")
    np_cfe = find_cfe_bitflips(np_mem, NOPROTECT_BLOCK_A, np_addrs)
    print(f"    Найдено {len(np_cfe)} CFE-событий")
 
    # 2. Для каждого — как ведёт себя YACCA-программа при ТОМ ЖЕ bit-flip
    print("\n[2] Детальный разбор каждого CFE:")
    print("-"*68)
 
    summary_table = []
    for i, e in enumerate(np_cfe, 1):
        addr, bit, orig = e['addr'], e['bit'], e['orig']
        faulted = e['faulted']
 
        # Найти тот же адрес в YACCA-программе
        ya_orig = ya_mem.get(addr, None)
        if ya_orig is not None:
            ya_faulted = u32(ya_orig ^ (1 << bit))
            ya_patched = inject_bitflip(ya_mem, addr, bit)
            try:
                ya_cpu = RV32CPU(ya_patched, pc_start=YACCA_BLOCK_A,
                                 trace=True, max_steps=200)
                ya_cpu.run()
                ya_outcome = classify_out(ya_cpu.output)
                ya_trace = ya_cpu.trace_log
                ya_steps = ya_cpu.steps
            except RuntimeError:
                ya_outcome = CRASH
                ya_trace = []
                ya_steps = 0
            ya_instr_dis = disasm(ya_orig, addr)
        else:
            ya_outcome = 'N/A'
            ya_trace = []
            ya_steps = 0
            ya_instr_dis = 'нет'
 
        print(f"\n  CFE #{i:02d}: addr=0x{addr:08X}, bit={bit}")
        print(f"  Незащищённая: 0x{orig:08X} ({disasm(orig, addr)})")
        print(f"    → flip bit{bit} → 0x{faulted:08X} ({disasm(faulted, addr)})")
        print(f"    Трасса ({e['steps']} шагов):")
        for l in e['trace']:
            print("      " + l.strip())
 
        print(f"  YACCA (тот же адрес/бит): 0x{ya_orig:08X} ({ya_instr_dis})" if ya_orig else "  YACCA: адрес вне программы")
        if ya_orig:
            print(f"    → flip bit{bit} → 0x{ya_faulted:08X} ({disasm(ya_faulted, addr)})")
            print(f"    Исход YACCA: {ya_outcome}  ({ya_steps} шагов)")
            if ya_trace:
                print(f"    Трасса YACCA:")
                for l in ya_trace:
                    print("      " + l.strip())
 
        summary_table.append({
            'cfe_n': i,
            'addr': f'0x{addr:08X}',
            'bit': bit,
            'np_instr': disasm(orig, addr),
            'np_faulted': disasm(faulted, addr),
            'ya_instr': ya_instr_dis,
            'ya_outcome': ya_outcome,
            'ya_steps': ya_steps,
        })
 
    # 3. Итоговая таблица
    print("\n" + "="*68)
    print("  СВОДНАЯ ТАБЛИЦА: CFE в noprotect → исход в YACCA")
    print("="*68)
    print(f"  {'#':>3}  {'Адрес':<14}  {'bit':>3}  {'NP-инструкция':<28}  "
          f"{'YACCA-инструкция':<28}  {'Исход YACCA':<12}")
    print(f"  {'─'*3}  {'─'*14}  {'─'*3}  {'─'*28}  {'─'*28}  {'─'*12}")
    for r in summary_table:
        icon = {'DETECTED': '✓ DETECTED', 'BENIGN': '→ BENIGN',
                'CFE': '✗ CFE', 'CRASH': '? CRASH', 'N/A': 'N/A'}.get(r['ya_outcome'], r['ya_outcome'])
        print(f"  {r['cfe_n']:>3}  {r['addr']:<14}  {r['bit']:>3}  "
              f"{r['np_instr']:<28}  {r['ya_instr']:<28}  {icon}")
 
    # 4. Анализ по категориям
    print("\n" + "="*68)
    print("  АНАЛИЗ: ПОЧЕМУ YACCA НЕ ДЕТЕКТИРУЕТ ВСЕ CFE")
    print("="*68)
 
    from collections import Counter
    ya_outcomes = Counter(r['ya_outcome'] for r in summary_table)
    print(f"\n  Из {len(summary_table)} CFE-событий в незащищённой программе:")
    for outcome, cnt in sorted(ya_outcomes.items()):
        pct = cnt / len(summary_table) * 100
        print(f"    {outcome:<12}: {cnt:>3}  ({pct:.1f}%)")
 
    print("\n  Объяснение категорий:")
    print("  DETECTED  — bit-flip изменил YACCA-инструкцию (проверку/обновление),")
    print("              мismatch сигнатуры обнаружен → error_handler")
    print("  BENIGN    — bit-flip затронул YACCA-код по тому же адресу, но")
    print("              новая инструкция не создаёт CFE в YACCA-программе")
    print("              (другая семантика из-за другой раскладки программы)")
    print("  CFE       — bit-flip в незащищённой программе даёт CFE;")
    print("              тот же bit-flip в YACCA тоже даёт CFE (YACCA пропустил)")
    print("  CRASH     — ни тот ни другой вариант не завершается корректно")
 
    # 5. Анализ уязвимых инструкций по типу поля
    print("\n" + "="*68)
    print("  АНАЛИЗ: КАКИЕ ПОЛЯ ИНСТРУКЦИЙ УЯЗВИМЫ")
    print("="*68)
    for e in np_cfe:
        addr, bit, orig = e['addr'], e['bit'], e['orig']
        op = orig & 0x7F
        if 12 <= bit <= 14 and op == 0x63:
            print(f"  ⚠ bit-flip в funct3 инструкции ветвления {disasm(orig, addr)}")
            print(f"    → 0x{addr:08X}: меняет BNE→BEQ или BEQ→BNE!")
        elif bit >= 20 and op == 0x6F:
            print(f"  ⚠ bit-flip в immediate JAL {disasm(orig, addr)}")
            print(f"    → 0x{addr:08X}: изменяет адрес перехода")
        elif 20 <= bit <= 31 and op == 0x13:
            print(f"  ⚠ bit-flip в immediate ADDI {disasm(orig, addr)}")
            print(f"    → 0x{addr:08X}: изменяет загружаемую константу")
 
if __name__ == '__main__':
    main()
 