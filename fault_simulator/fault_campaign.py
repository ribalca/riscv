#!/usr/bin/env python3
"""
fault_campaign.py — Систематическая fault-кампания для biRISC-V (ISA-уровень)

Модель ошибки: bit-flip в слове инструкции (1 бит за раз).
Охват: все адреса инструкций × 32 бита × 2 программы (с/без YACCA).

Классы исходов:
  BENIGN   — результат совпадает со штатным (DENY)
  CFE      — управление нарушено (GRANT или нештатный путь)
  DETECTED — YACCA сработал (только для защищённой версии)
  CRASH    — таймаут / исключение симулятора

Ключевой вопрос 1: какой % bit-flip'ов в biRISC-V программах приводит к CFE?
Ключевой вопрос 2: какой % CFE обнаруживает YACCA? (detection rate)
"""

import sys, itertools, time, json, csv
from dataclasses import dataclass, field
from typing import Optional

# Добавляем путь к симулятору
sys.path.insert(0, '.')
from riscv_sim import RV32CPU, u32
from programs import (
    make_noprotect, make_yacca,
    NOPROTECT_BLOCK_A, NOPROTECT_BLOCK_B, NOPROTECT_BLOCK_C, NOPROTECT_BLOCK_D,
    YACCA_BLOCK_A, YACCA_BLOCK_B, YACCA_BLOCK_C, YACCA_BLOCK_D, YACCA_ERROR,
    RESULT_GRANTED, RESULT_DENIED, RESULT_ERROR,
    B_A, B_B, CODE_INIT,
)

BASE = 0x80000000

# ─── Outcome constants ────────────────────────────────────────────────────────
BENIGN   = 'BENIGN'    # результат = штатный (DENY)
CFE      = 'CFE'       # нарушение потока управления (GRANT)
DETECTED = 'DETECTED'  # YACCA обнаружил атаку
CRASH    = 'CRASH'     # таймаут / неизвестный исход

# ─── Single experiment ────────────────────────────────────────────────────────

def run_one(memory: dict, pc_start: int, max_steps: int = 500) -> tuple[str, Optional[int]]:
    """
    Запустить один прогон симуляции.
    Возвращает (outcome, output_value).
    """
    try:
        cpu = RV32CPU(memory, pc_start=pc_start, trace=False, max_steps=max_steps)
        cpu.run()
        out = cpu.output
        if out is None:
            return CRASH, None
        signed = out if out < 0x80000000 else out - 0x100000000
        if signed == RESULT_DENIED:
            return BENIGN, out
        if signed == RESULT_GRANTED:
            return CFE, out
        if signed == RESULT_ERROR:
            return DETECTED, out
        return CRASH, out
    except Exception:
        return CRASH, None


def inject_bitflip(memory: dict, addr: int, bit: int) -> dict:
    """Инвертировать бит `bit` в слове по адресу `addr`."""
    patched = dict(memory)
    original = patched.get(addr, 0)
    patched[addr] = u32(original ^ (1 << bit))
    return patched

# ─── Full campaign ────────────────────────────────────────────────────────────

@dataclass
class CampaignResult:
    label: str
    pc_start: int
    # Счётчики по итогу
    counts: dict = field(default_factory=lambda: {BENIGN:0, CFE:0, DETECTED:0, CRASH:0})
    # Детальные записи: список dict
    records: list = field(default_factory=list)
    total: int = 0

    def add(self, addr: int, bit: int, orig: int, faulted: int,
            outcome: str, out_val):
        self.counts[outcome] += 1
        self.total += 1
        self.records.append({
            'addr':    f'0x{addr:08X}',
            'bit':     bit,
            'orig':    f'0x{orig:08X}',
            'faulted': f'0x{faulted:08X}',
            'outcome': outcome,
            'a0':      f'0x{out_val & 0xFFFFFFFF:08X}' if out_val is not None else 'N/A',
        })

    def pct(self, key):
        return self.counts[key] / self.total * 100 if self.total else 0


def run_campaign(label: str, memory: dict, pc_start: int,
                 instruction_addrs: list, verbose: bool = True) -> CampaignResult:
    result = CampaignResult(label=label, pc_start=pc_start)

    # Эталонный прогон (без fault)
    baseline_outcome, baseline_out = run_one(memory, pc_start)

    if verbose:
        print(f'\n{"═"*62}')
        print(f'  Кампания: {label}')
        print(f'  Инструкций в программе : {len(instruction_addrs)}')
        print(f'  Bit-flip точек          : {len(instruction_addrs) * 32}')
        print(f'  Эталонный исход         : {baseline_outcome}  (a0=0x{baseline_out & 0xFFFFFFFF:08X})')
        print(f'{"═"*62}')

    for addr in instruction_addrs:
        orig = memory.get(addr, 0)
        for bit in range(32):
            faulted_word = u32(orig ^ (1 << bit))
            patched = inject_bitflip(memory, addr, bit)
            outcome, out_val = run_one(patched, pc_start)
            result.add(addr, bit, orig, faulted_word, outcome, out_val)

    return result

# ─── Analysis helpers ──────────────────────────────────────────────────────────

def per_address_stats(result: CampaignResult, addrs: list) -> list:
    """
    Для каждого адреса инструкции подсчитать исходы по 32 битам.
    Возвращает список dict с полями addr, benign, cfe, detected, crash.
    """
    from collections import defaultdict
    by_addr = defaultdict(lambda: {BENIGN:0, CFE:0, DETECTED:0, CRASH:0})
    for rec in result.records:
        by_addr[rec['addr']][rec['outcome']] += 1
    rows = []
    for a in addrs:
        key = f'0x{a:08X}'
        d = by_addr[key]
        rows.append({
            'addr': key,
            BENIGN:   d[BENIGN],
            CFE:      d[CFE],
            DETECTED: d[DETECTED],
            CRASH:    d[CRASH],
        })
    return rows


def detection_rate(np_result: CampaignResult, ya_result: CampaignResult) -> dict:
    """
    Ключевая метрика: из CFE, которые возникли в незащищённой программе,
    сколько % обнаружила YACCA?
    """
    # Сопоставим по (addr, bit)
    np_map = {(r['addr'], r['bit']): r['outcome'] for r in np_result.records}
    ya_map = {(r['addr'], r['bit']): r['outcome'] for r in ya_result.records}

    both_cfe    = 0  # CFE в обеих версиях
    ya_detected = 0  # из них YACCA обнаружил
    ya_benign   = 0  # YACCA сделал BENIGN (нет CFE)
    ya_cfe      = 0  # YACCA тоже пропустил CFE

    np_cfe_total = sum(1 for v in np_map.values() if v == CFE)

    for key, np_out in np_map.items():
        if np_out != CFE:
            continue
        ya_out = ya_map.get(key, CRASH)
        both_cfe += 1
        if ya_out == DETECTED:
            ya_detected += 1
        elif ya_out == BENIGN:
            ya_benign += 1
        elif ya_out == CFE:
            ya_cfe += 1

    dr = ya_detected / both_cfe * 100 if both_cfe else 0
    return {
        'np_cfe_total':  np_cfe_total,
        'both_cfe':      both_cfe,
        'ya_detected':   ya_detected,
        'ya_benign':     ya_benign,
        'ya_cfe_missed': ya_cfe,
        'detection_rate': dr,
    }


def print_summary(np_r: CampaignResult, ya_r: CampaignResult, dr: dict):
    W = 62
    print(f'\n{"═"*W}')
    print('  РЕЗУЛЬТАТЫ СИСТЕМАТИЧЕСКОЙ FAULT-КАМПАНИИ')
    print(f'{"═"*W}')

    def prow(label, np_v, ya_v, pct_np='', pct_ya=''):
        pn = f'({pct_np:.1f}%)' if pct_np != '' else ''
        py = f'({pct_ya:.1f}%)' if pct_ya != '' else ''
        print(f'  {label:<28} {np_v:>5} {pn:<9}  {ya_v:>5} {py:<9}')

    print(f'  {"Метрика":<28} {"Без YACCA":>14}  {"С YACCA":>14}')
    print(f'  {"─"*28} {"─"*14}  {"─"*14}')
    tot = np_r.total
    prow('Всего экспериментов', tot, ya_r.total)
    prow('BENIGN (штатный исход)',
         np_r.counts[BENIGN], ya_r.counts[BENIGN],
         np_r.pct(BENIGN), ya_r.pct(BENIGN))
    prow('CFE (нарушение потока)',
         np_r.counts[CFE], ya_r.counts[CFE],
         np_r.pct(CFE), ya_r.pct(CFE))
    prow('DETECTED (обнаружено YACCA)',
         np_r.counts[DETECTED], ya_r.counts[DETECTED],
         np_r.pct(DETECTED), ya_r.pct(DETECTED))
    prow('CRASH (таймаут/ошибка)',
         np_r.counts[CRASH], ya_r.counts[CRASH],
         np_r.pct(CRASH), ya_r.pct(CRASH))

    print(f'\n{"─"*W}')
    print('  КЛЮЧЕВЫЕ МЕТРИКИ:')
    print(f'{"─"*W}')
    cfe_rate_np = np_r.pct(CFE)
    print(f'  CFE rate (без YACCA) : {np_r.counts[CFE]} / {tot}'
          f'  = {cfe_rate_np:.1f}% bit-flip\'ов приводят к CFE')
    print(f'  CFE rate (с YACCA)   : {ya_r.counts[CFE]} / {ya_r.total}'
          f'  = {ya_r.pct(CFE):.1f}%')
    print()
    print(f'  Из {dr["both_cfe"]} CFE (незащищённая программа):')
    print(f'    YACCA обнаружил  : {dr["ya_detected"]:>4}  '
          f'({dr["detection_rate"]:.1f}%)  ← detection rate')
    print(f'    YACCA сделал BENIGN: {dr["ya_benign"]:>3}  '
          f'(YACCA подавил CFE без ошибки)')
    print(f'    YACCA пропустил  : {dr["ya_cfe_missed"]:>4}  '
          f'(silent CFE — необнаруженные)')
    print(f'{"═"*W}')


def print_per_address(label: str, rows: list, is_yacca: bool = False):
    print(f'\n  Детализация по адресам ({label}):')
    header = f'  {"Адрес":<14} {"BENIGN":>7} {"CFE":>7}'
    if is_yacca:
        header += f' {"DETECTED":>9}'
    header += f' {"CRASH":>7}  Уязвим?'
    print(header)
    print('  ' + '─' * (len(header) - 2))
    for r in rows:
        vuln = '⚠ ДА' if r[CFE] > 0 else '—'
        line = f'  {r["addr"]:<14} {r[BENIGN]:>7} {r[CFE]:>7}'
        if is_yacca:
            line += f' {r[DETECTED]:>9}'
        line += f' {r[CRASH]:>7}  {vuln}'
        print(line)


def save_csv(result: CampaignResult, path: str):
    if not result.records:
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=result.records[0].keys())
        w.writeheader()
        w.writerows(result.records)
    print(f'  → CSV сохранён: {path}')


def save_json(data, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f'  → JSON сохранён: {path}')

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    verbose = '--quiet' not in sys.argv
    save    = '--save'  in sys.argv

    print('Построение программ...')
    _, np_mem, _ = make_noprotect()
    _, ya_mem, _ = make_yacca()

    np_addrs = sorted(np_mem.keys())
    ya_addrs = sorted(ya_mem.keys())

    t0 = time.perf_counter()

    np_result = run_campaign(
        'Без YACCA (auth_noprotect)',
        np_mem, NOPROTECT_BLOCK_A, np_addrs, verbose=verbose)

    ya_result = run_campaign(
        'С YACCA_CMP (auth_yacca)',
        ya_mem, YACCA_BLOCK_A, ya_addrs, verbose=verbose)

    elapsed = time.perf_counter() - t0

    dr = detection_rate(np_result, ya_result)

    print_summary(np_result, ya_result, dr)

    np_per_addr = per_address_stats(np_result, np_addrs)
    ya_per_addr = per_address_stats(ya_result, ya_addrs)

    print_per_address('Без YACCA', np_per_addr, is_yacca=False)
    print_per_address('С YACCA',   ya_per_addr, is_yacca=True)

    print(f'\n  Время кампании: {elapsed:.2f} с '
          f'({np_result.total + ya_result.total} экспериментов)')

    if save:
        save_csv(np_result, '/tmp/campaign_noprotect.csv')
        save_csv(ya_result, '/tmp/campaign_yacca.csv')
        summary = {
            'np_counts':     np_result.counts,
            'ya_counts':     ya_result.counts,
            'np_total':      np_result.total,
            'ya_total':      ya_result.total,
            'detection_rate': dr,
            'np_per_addr':   np_per_addr,
            'ya_per_addr':   ya_per_addr,
        }
        save_json(summary, '/tmp/campaign_summary.json')

    return dr, np_result, ya_result, np_per_addr, ya_per_addr


if __name__ == '__main__':
    main()
