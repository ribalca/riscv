#!/usr/bin/env python3
"""
visualize.py – Визуальная демонстрация YACCA fault injection

Режимы:
  python3 visualize.py           → анимация (GIF)  yacca_demo.gif
  python3 visualize.py --static  → статичная PNG    yacca_demo.png
  python3 visualize.py --term    → rich-терминал    (трассировка)
  python3 visualize.py --all     → все три режима
"""

import sys, copy
sys.path.insert(0, '.')

from programs import (
    make_noprotect, make_yacca, inject_fault,
    NOPROTECT_BLOCK_A, NOPROTECT_BLOCK_B, NOPROTECT_BLOCK_C,
    NOPROTECT_BLOCK_D, NOPROTECT_FAULT_PC,
    YACCA_BLOCK_A, YACCA_BLOCK_B, YACCA_BLOCK_C,
    YACCA_BLOCK_D, YACCA_ERROR, YACCA_FAULT_PC,
    RESULT_GRANTED, RESULT_DENIED, RESULT_ERROR,
    B_A, B_B, CODE_INIT,
)
from riscv_sim import RV32CPU, disasm

BASE = 0x80000000

# ── Цвета ─────────────────────────────────────────────────────────────────────
C = {
    'bg':      '#0D1117',
    'panel':   '#161B22',
    'border':  '#30363D',
    'text':    '#E6EDF3',
    'dim':     '#6E7681',
    'block_a': '#2D7DD2',
    'block_b': '#F4A261',
    'block_c': '#E63946',
    'block_d': '#2EC4B6',
    'error':   '#9B5DE5',
    'edge_ok': '#6E7681',
    'edge_hi': '#F4D03F',
    'fault':   '#FF006E',
    'ok':      '#2EC4B6',
    'bad':     '#E63946',
    'warn':    '#F4A261',
}

BLOCK_COLORS = {
    'A': C['block_a'],
    'B': C['block_b'],
    'C': C['block_c'],
    'D': C['block_d'],
    'E': C['error'],
}
BLOCK_LABELS = {
    'A': ('Block A', 'Инициализация'),
    'B': ('Block B', 'Проверка токена'),
    'C': ('Block C', 'GRANT ACCESS'),
    'D': ('Block D', 'DENY ACCESS'),
    'E': ('Error', 'CFE detected!'),
}
BLOCK_W, BLOCK_H = 0.30, 0.12

# Позиции блоков в осях (cx, cy)
BLOCK_POS = {
    'A': (0.50, 0.86),
    'B': (0.50, 0.63),
    'C': (0.25, 0.38),
    'D': (0.75, 0.38),
    'E': (0.50, 0.14),
}


# ══════════════════════════════════════════════════════════════════════════════
#  1. Симуляция с захватом состояния по шагам
# ══════════════════════════════════════════════════════════════════════════════

def classify_pc(pc, block_map):
    for name, (start, end) in block_map.items():
        if start <= pc < end:
            return name
    return None


def run_sim_detailed(memory, pc_start, block_map, fault_pc=None):
    """Пошаговая симуляция; возвращает (output, frames)."""
    cpu = RV32CPU(memory, pc_start=pc_start, trace=True, max_steps=50_000)
    frames = []
    visited_set   = set()
    visited_list  = []
    visited_edges = set()
    prev_block    = None
    fault_pcs     = {fault_pc} if fault_pc is not None else set()

    while not cpu.halted and cpu.steps < 50_000:
        cpu.step()
        if not cpu.trace_log:
            break
        line = cpu.trace_log[-1].strip()
        try:
            pc_s    = line[1:9]
            instr_s = line[11:19]
            dis_s   = line[21:]
            pc_i    = int(pc_s, 16)
        except Exception:
            break

        block = classify_pc(pc_i, block_map)
        if block and block not in visited_set:
            visited_set.add(block)
            visited_list.append(block)
        if prev_block and block and block != prev_block:
            visited_edges.add((prev_block, block))

        frames.append({
            'pc':       pc_i,
            'instr':    instr_s,
            'dis':      dis_s,
            'block':    block,
            'regs':     {
                't0': cpu.regs[5],
                't1': cpu.regs[6],
                't4': cpu.regs[29],
                't5': cpu.regs[30],
                'a0': cpu.regs[10],
            },
            'visited':  list(visited_list),
            'edges':    set(visited_edges),
            'is_fault': pc_i in fault_pcs,
        })
        if block:
            prev_block = block

    return cpu.output, frames


def interpret_output(output, emoji=True):
    if output is None:
        return "TIMEOUT", C['warn']
    val = output if output < 0x80000000 else output - 0x100000000
    if val == RESULT_GRANTED:
        return ("ACCESS GRANTED [!]" if not emoji else "ACCESS GRANTED \u274c"), C['bad']
    if val == RESULT_DENIED:
        return "ACCESS DENIED \u2713", C['ok']
    if val == RESULT_ERROR:
        return ("CFE DETECTED [OK]" if not emoji else "CFE DETECTED \U0001f6e1"), C['ok']
    return f"0x{output:08X}", C['warn']


NP_BLOCK_MAP = {
    'A': (NOPROTECT_BLOCK_A, NOPROTECT_BLOCK_B),
    'B': (NOPROTECT_BLOCK_B, NOPROTECT_BLOCK_C),
    'C': (NOPROTECT_BLOCK_C, NOPROTECT_BLOCK_D),
    'D': (NOPROTECT_BLOCK_D, BASE + 0x200),
}
YA_BLOCK_MAP = {
    'A': (YACCA_BLOCK_A, YACCA_BLOCK_B),
    'B': (YACCA_BLOCK_B, YACCA_BLOCK_C),
    'C': (YACCA_BLOCK_C, YACCA_BLOCK_D),
    'D': (YACCA_BLOCK_D, YACCA_ERROR),
    'E': (YACCA_ERROR,   BASE + 0x200),
}


def prepare_experiments():
    """Запустить все 4 эксперимента и вернуть список dataset-ов."""
    _, np_mem, _ = make_noprotect()
    _, ya_mem, _ = make_yacca()
    np_fault_mem = inject_fault(np_mem, NOPROTECT_FAULT_PC, NOPROTECT_BLOCK_C)
    ya_fault_mem = inject_fault(ya_mem, YACCA_FAULT_PC,    YACCA_BLOCK_C)

    specs = [
        (1, "Без защиты  |  Без атаки",  np_mem,       NP_BLOCK_MAP, False, None),
        (2, "Без защиты  |  FAULT ⚡",   np_fault_mem, NP_BLOCK_MAP, True,  NOPROTECT_FAULT_PC),
        (3, "YACCA  |  Без атаки",        ya_mem,       YA_BLOCK_MAP, False, None),
        (4, "YACCA  |  FAULT ⚡",         ya_fault_mem, YA_BLOCK_MAP, True,  YACCA_FAULT_PC),
    ]

    datasets = []
    for num, label, mem, bmap, is_fault, fpc in specs:
        out, frames = run_sim_detailed(mem, NOPROTECT_BLOCK_A if not bmap.get('E') else YACCA_BLOCK_A,
                                        bmap, fault_pc=fpc)
        text, color = interpret_output(out, emoji=False)
        datasets.append({
            'num':      num,
            'label':    label,
            'frames':   frames,
            'output':   out,
            'text':     text,
            'color':    color,
            'is_fault': is_fault,
            'is_yacca': ('E' in bmap),
            'bmap':     bmap,
            'fault_pc': fpc,
        })
    return datasets


# ══════════════════════════════════════════════════════════════════════════════
#  2. Рисование CFG (для animation и static)
# ══════════════════════════════════════════════════════════════════════════════

def _draw_block(ax, cx, cy, label, sub, fill, alpha=1.0, lw=1.5,
                border=None, pulse=False):
    import matplotlib.patches as mp
    W, H = BLOCK_W, BLOCK_H
    bc = border or fill

    # тень
    ax.add_patch(mp.FancyBboxPatch(
        (cx - W/2 + 0.004, cy - H/2 - 0.004), W, H,
        boxstyle="round,pad=0.01", facecolor='#000', edgecolor='none',
        alpha=alpha * 0.35, transform=ax.transAxes, zorder=2))

    # блок
    ax.add_patch(mp.FancyBboxPatch(
        (cx - W/2, cy - H/2), W, H,
        boxstyle="round,pad=0.01", facecolor=fill, edgecolor=bc,
        linewidth=lw, alpha=alpha, transform=ax.transAxes, zorder=3))

    # если текущий – дополнительный ободок
    if pulse:
        ax.add_patch(mp.FancyBboxPatch(
            (cx - W/2 - 0.008, cy - H/2 - 0.008), W + 0.016, H + 0.016,
            boxstyle="round,pad=0.01", facecolor='none',
            edgecolor='#FFFFFF', linewidth=2.5, alpha=0.7,
            transform=ax.transAxes, zorder=3))

    ax.text(cx, cy + 0.015, label, ha='center', va='center',
            fontsize=9, fontweight='bold', color='white',
            transform=ax.transAxes, zorder=4, alpha=alpha)
    ax.text(cx, cy - 0.020, sub, ha='center', va='center',
            fontsize=7, color='white', alpha=alpha * 0.80,
            transform=ax.transAxes, zorder=4)


def _arrow(ax, x1, y1, x2, y2, color, lw, alpha=1.0, rad=0.0, dashed=False):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                xycoords='axes fraction', textcoords='axes fraction',
                zorder=1, alpha=alpha,
                arrowprops=dict(
                    arrowstyle='->', color=color, lw=lw,
                    linestyle='dashed' if dashed else 'solid',
                    mutation_scale=13,
                    connectionstyle=f'arc3,rad={rad}',
                ))


def draw_cfg(ax, visited_blocks, visited_edges, current_block,
             show_yacca, show_fault, result_text, result_color,
             fault_active=False):
    """Отрисовать CFG с анимационным выделением."""
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_facecolor(C['panel'])
    ax.set_xticks([]); ax.set_yticks([])
    for sp in ax.spines.values():
        sp.set_edgecolor(C['border'])

    W, H = BLOCK_W, BLOCK_H

    # ── Нарисовать рёбра ──────────────────────────────────────────────────
    cfg_edges = [('A','B'), ('B','C'), ('B','D')]
    if show_yacca:
        cfg_edges += [('B','E'), ('C','E'), ('D','E')]

    x_off = {'C': -0.02, 'D': +0.02}

    for (src, dst) in cfg_edges:
        sx, sy = BLOCK_POS[src]
        dx, dy = BLOCK_POS[dst]
        vis = (src, dst) in visited_edges
        col  = C['edge_hi'] if vis else C['edge_ok']
        lw   = 2.2 if vis else 1.0
        alp  = 1.0 if vis else 0.30

        xo = x_off.get(dst, 0)
        if dst == 'E' and src == 'B':
            _arrow(ax, sx + W/2, sy, BLOCK_POS['E'][0] + W/2,
                   BLOCK_POS['E'][1] + H/2, col, lw, alp, rad=-0.5, dashed=True)
        elif dst == 'E':
            dx_off = 0.11 if src == 'C' else -0.11
            _arrow(ax, sx, sy - H/2,
                   BLOCK_POS['E'][0] + dx_off, BLOCK_POS['E'][1] + H/2,
                   col, lw, alp, rad=0.4, dashed=True)
        else:
            _arrow(ax, sx + xo, sy - H/2, dx + xo, dy + H/2, col, lw, alp)

    # ── Fault-ребро: A → C ────────────────────────────────────────────────
    if show_fault:
        fa  = 0.95 if fault_active else 0.45
        flw = 2.8  if fault_active else 1.8
        _arrow(ax,
               BLOCK_POS['A'][0] - W/2, BLOCK_POS['A'][1],
               BLOCK_POS['C'][0] - W/2 + 0.015, BLOCK_POS['C'][1] + H/2,
               C['fault'], flw, fa, rad=-0.42, dashed=True)
        # метка fault
        ax.text(0.04, 0.60, '⚡ FAULT', ha='center', va='center',
                fontsize=7.5, color=C['fault'], fontweight='bold',
                transform=ax.transAxes, alpha=fa,
                bbox=dict(boxstyle='round,pad=0.2', facecolor=C['bg'],
                          edgecolor=C['fault'], lw=0.8))

    # ── Нарисовать блоки ──────────────────────────────────────────────────
    for name, (cx, cy) in BLOCK_POS.items():
        if name == 'E' and not show_yacca:
            continue
        lbl, sub = BLOCK_LABELS[name]
        is_cur   = (name == current_block)
        is_vis   = name in visited_blocks
        fill     = BLOCK_COLORS[name]
        alpha    = 1.0 if is_vis else 0.26
        lw       = 3.0 if is_cur else (1.8 if is_vis else 1.0)
        bc       = '#FFFFFF' if is_cur else fill

        # "Цель атаки" метка
        if name == 'C' and show_fault:
            ax.text(cx, cy + H/2 + 0.042, '⚡ Цель атаки',
                    ha='center', va='bottom', fontsize=6.5,
                    color=C['fault'], fontweight='bold',
                    transform=ax.transAxes, alpha=0.9)

        _draw_block(ax, cx, cy, lbl, sub, fill,
                    alpha=alpha, lw=lw, border=bc, pulse=is_cur)

    # ── Итог ──────────────────────────────────────────────────────────────
    if result_text:
        ax.text(0.50, 0.025, result_text,
                ha='center', va='bottom', fontsize=8.5, fontweight='bold',
                color=result_color, transform=ax.transAxes,
                bbox=dict(boxstyle='round,pad=0.3', facecolor=C['bg'],
                          edgecolor=result_color, lw=1.5))


# ══════════════════════════════════════════════════════════════════════════════
#  3. Анимация
# ══════════════════════════════════════════════════════════════════════════════

INTRO_FRAMES   = 6
RESULT_FRAMES  = 10
TRANS_FRAMES   = 3

EXP_TITLES = [
    "Эксп. 1: Без защиты | Без атаки",
    "Эксп. 2: Без защиты | FAULT",
    "Эксп. 3: YACCA | Без атаки",
    "Эксп. 4: YACCA | FAULT",
]
BORDER_COLS = [C['ok'], C['bad'], C['ok'], C['ok']]


def build_global_frames(datasets):
    """Строим список (фаза, exp_idx, step_idx)."""
    gf = []
    for ei, exp in enumerate(datasets):
        for _ in range(INTRO_FRAMES):
            gf.append(('intro', ei, 0))
        for si in range(len(exp['frames'])):
            gf.append(('exec', ei, si))
        for _ in range(RESULT_FRAMES):
            gf.append(('result', ei, len(exp['frames']) - 1))
        if ei < len(datasets) - 1:
            for _ in range(TRANS_FRAMES):
                gf.append(('trans', ei, 0))
    return gf


def _setup_axes(fig):
    import matplotlib.gridspec as gs
    spec = gs.GridSpec(2, 2, figure=fig,
                       left=0.04, right=0.97,
                       top=0.91, bottom=0.03,
                       wspace=0.05, hspace=0.0,
                       height_ratios=[1, 13])
    ax_head = fig.add_subplot(spec[0, :])
    ax_cfg  = fig.add_subplot(spec[1, 0])
    ax_info = fig.add_subplot(spec[1, 1])
    return ax_head, ax_cfg, ax_info


def _draw_header(ax, exp, phase, step_idx):
    ax.set_facecolor(C['bg'])
    ax.set_xticks([]); ax.set_yticks([])
    for sp in ax.spines.values():
        sp.set_visible(False)

    bc = BORDER_COLS[exp['num'] - 1]
    ax.text(0.5, 0.5, f"[{exp['num']}/4]  {exp['label']}",
            ha='center', va='center',
            fontsize=11, fontweight='bold', color=C['text'],
            transform=ax.transAxes,
            bbox=dict(boxstyle='round,pad=0.3', facecolor=C['panel'],
                      edgecolor=bc, lw=1.8))

    if phase == 'exec':
        total = len(exp['frames'])
        progress = (step_idx + 1) / total
        ax.add_patch(__import__('matplotlib.patches', fromlist=['FancyBboxPatch'])
                     .FancyBboxPatch(
            (0.01, 0.04), 0.98 * progress, 0.12,
            boxstyle="square,pad=0", facecolor=bc, edgecolor='none',
            alpha=0.25, transform=ax.transAxes))


def _draw_info(ax, exp, phase, step_idx):
    ax.set_facecolor(C['panel'])
    ax.set_xticks([]); ax.set_yticks([])
    for sp in ax.spines.values():
        sp.set_edgecolor(C['border'])

    lines = []

    if phase == 'intro':
        lines += [
            ('bold', f"{'='*36}"),
            ('title', f"Эксперимент {exp['num']}: {exp['label']}"),
            ('bold', f"{'='*36}"),
            ('', ''),
            ('key', 'Сценарий: secure boot token check'),
            ('val', f"user_token = 0x00  (НЕ авторизован)"),
            ('val', f"secret_key = 0x50  (правильный)"),
            ('', ''),
        ]
        if exp['is_yacca']:
            lines += [
                ('key', 'YACCA защита ВКЛЮЧЕНА'),
                ('val', f"code-register t5 = {CODE_INIT} (начало)"),
                ('val', f"Ожидаем B_A={B_A} после Block A"),
                ('val', f"Ожидаем B_B={B_B} после Block B"),
            ]
        else:
            lines += [('key', 'YACCA защита ВЫКЛЮЧЕНА')]
        if exp['is_fault']:
            lines += [('', ''), ('fault', 'FAULT будет инжектирован!'),
                      ('fault', 'j block_b → j block_c')]

    elif phase in ('exec', 'result'):
        frame = exp['frames'][step_idx]
        total = len(exp['frames'])
        n = step_idx + 1

        lines.append(('bold', f"Шаг {n} / {total}"))
        lines.append(('', ''))

        # Текущая инструкция
        lines.append(('key', 'Инструкция:'))
        pc_str = f"0x{frame['pc']:08X}"
        lines.append(('val', f"PC: {pc_str}"))
        lines.append(('val', f"{frame['dis']}"))

        if frame['is_fault']:
            lines.append(('fault', '  ⚡ FAULT INJECTION HERE!'))
        lines.append(('', ''))

        # Блок
        blk = frame['block']
        if blk:
            lines.append(('key', f"Блок: {BLOCK_LABELS[blk][0]}"))
            lines.append(('', ''))

        # Регистры
        r = frame['regs']
        lines.append(('key', 'Регистры:'))
        lines.append(('val', f"t0 = 0x{r['t0']:08X}  (user_token)"))
        lines.append(('val', f"t1 = 0x{r['t1']:08X}  (secret_key)"))
        if exp['is_yacca']:
            lines.append(('val', f"t5 = 0x{r['t5']:08X}  (YACCA code)"))
            lines.append(('val', f"t4 = 0x{r['t4']:08X}  (YACCA temp)"))
        lines.append(('', ''))

        # Путь
        path_str = ' → '.join(frame['visited']) if frame['visited'] else '-'
        lines.append(('key', f"Путь: {path_str}"))

        if phase == 'result':
            lines.append(('', ''))
            lines.append(('bold', '-' * 30))
            col_map = {C['ok']: 'result_ok', C['bad']: 'result_bad'}
            style = col_map.get(exp['color'], 'result_ok')
            lines.append((style, f"Результат: {exp['text']}"))
            lines.append(('bold', '-' * 30))

    # Рисуем линии
    y = 0.97
    dy = 0.054
    STYLE_COLORS = {
        'bold':   C['text'],
        'title':  C['text'],
        'key':    '#58A6FF',
        'val':    C['dim'],
        'fault':  C['fault'],
        'result_ok':  C['ok'],
        'result_bad': C['bad'],
        '':       C['dim'],
    }
    STYLE_BOLD = {'bold', 'title', 'result_ok', 'result_bad'}

    for style, text in lines:
        col = STYLE_COLORS.get(style, C['text'])
        fw  = 'bold' if style in STYLE_BOLD else 'normal'
        fs  = 9 if style in ('bold', 'title', 'key') else 8
        ax.text(0.04, y, text, ha='left', va='top',
                fontsize=fs, color=col, fontweight=fw,
                transform=ax.transAxes,
                fontfamily='monospace')
        y -= dy


def _frame_update(fi, global_frames, datasets, fig, axes):
    ax_head, ax_cfg, ax_info = axes
    for ax in axes:
        ax.clear()

    phase, ei, si = global_frames[fi]
    exp = datasets[ei]

    _draw_header(ax_head, exp, phase, si)

    if phase == 'trans':
        ax_cfg.set_facecolor(C['bg'])
        ax_cfg.set_xticks([]); ax_cfg.set_yticks([])
        ax_info.set_facecolor(C['bg'])
        ax_info.set_xticks([]); ax_info.set_yticks([])
        return

    frame = exp['frames'][si]
    cur_block = frame['block'] if phase == 'exec' else None
    is_fault_step = frame['is_fault'] if phase == 'exec' else False
    result_text = exp['text'] if phase == 'result' else None
    result_col  = exp['color'] if phase == 'result' else C['dim']

    visited = frame['visited'] if phase != 'intro' else []
    edges   = frame['edges']   if phase != 'intro' else set()

    draw_cfg(ax_cfg, visited, edges,
             current_block=cur_block,
             show_yacca=exp['is_yacca'],
             show_fault=exp['is_fault'],
             result_text=result_text,
             result_color=result_col,
             fault_active=is_fault_step)

    _draw_info(ax_info, exp, phase, si)


def run_animation(datasets, save_path='yacca_demo.gif'):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.animation import FuncAnimation, PillowWriter

    global_frames = build_global_frames(datasets)

    fig = plt.figure(figsize=(13, 7.5), facecolor=C['bg'])
    fig.suptitle('YACCA Fault Injection Demo  ·  biRISC-V / RISC-V RV32I',
                 fontsize=12, fontweight='bold', color=C['text'], y=0.99)

    ax_head, ax_cfg, ax_info = _setup_axes(fig)
    axes = (ax_head, ax_cfg, ax_info)

    anim = FuncAnimation(
        fig,
        func=lambda fi: _frame_update(fi, global_frames, datasets, fig, axes),
        frames=len(global_frames),
        interval=250,
        repeat=True,
    )

    print(f"  Сохранение {save_path}  ({len(global_frames)} кадров) ...")
    anim.save(save_path, writer=PillowWriter(fps=4), dpi=100)
    print(f"  [✓] Сохранено: {save_path}")
    plt.close(fig)


# ══════════════════════════════════════════════════════════════════════════════
#  4. Статичная PNG (4 панели)
# ══════════════════════════════════════════════════════════════════════════════

def _static_visited_all(exp):
    """Все блоки и рёбра из последнего кадра."""
    if not exp['frames']:
        return [], set()
    f = exp['frames'][-1]
    return f['visited'], f['edges']


def run_static(datasets, save_path='yacca_demo.png'):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gs
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D

    fig = plt.figure(figsize=(14, 10), facecolor=C['bg'])
    fig.suptitle('YACCA Fault Injection Demo  ·  biRISC-V (RISC-V RV32I)',
                 fontsize=14, fontweight='bold', color=C['text'], y=0.97)

    spec = gs.GridSpec(2, 2, figure=fig,
                       left=0.05, right=0.97,
                       top=0.91, bottom=0.07,
                       wspace=0.07, hspace=0.14)

    for i, exp in enumerate(datasets):
        ax = fig.add_subplot(spec[i // 2, i % 2])
        bc = BORDER_COLS[i]
        ax.set_title(
            f"Эксперимент {exp['num']}\n{exp['label']}",
            fontsize=9.5, fontweight='bold', color=C['text'], pad=5,
            bbox=dict(boxstyle='round,pad=0.3', facecolor=C['panel'],
                      edgecolor=bc, lw=1.5))
        vis, edges = _static_visited_all(exp)
        draw_cfg(ax, vis, edges, current_block=None,
                 show_yacca=exp['is_yacca'], show_fault=exp['is_fault'],
                 result_text=f"{exp['text']}  ({len(exp['frames'])} шагов)",
                 result_color=exp['color'])

    legend_items = [
        Patch(facecolor=C['block_a'], label='Block A – Инициализация'),
        Patch(facecolor=C['block_b'], label='Block B – Проверка токена'),
        Patch(facecolor=C['block_c'], label='Block C – GRANT (цель атаки)'),
        Patch(facecolor=C['block_d'], label='Block D – DENY (безопасный)'),
        Patch(facecolor=C['error'],   label='Error Handler – CFE detected'),
        Line2D([0],[0], color=C['edge_hi'], lw=2,        label='Пройденный путь'),
        Line2D([0],[0], color=C['fault'],   lw=2, ls='--', label='Fault-инъекция'),
    ]
    fig.legend(handles=legend_items, loc='lower center', ncol=4,
               facecolor=C['panel'], edgecolor=C['border'],
               labelcolor=C['text'], fontsize=8,
               bbox_to_anchor=(0.5, 0.00))

    fig.text(0.5, 0.045,
             "YACCA: END блока X → code ^= M2_X  │  START блока Y → if code ≠ B_pred → error",
             ha='center', fontsize=8, color=C['dim'], style='italic')

    plt.savefig(save_path, dpi=150, bbox_inches='tight', facecolor=C['bg'])
    print(f"  [✓] Сохранено: {save_path}")
    plt.close(fig)


# ══════════════════════════════════════════════════════════════════════════════
#  5. Rich-терминал
# ══════════════════════════════════════════════════════════════════════════════

def run_terminal(datasets):
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.align import Align
    from rich import box as rbox
    from rich.rule import Rule

    console = Console()
    console.print()
    console.rule("[bold cyan]YACCA Fault Injection Demo  ·  biRISC-V / RISC-V RV32I[/]")
    console.print()

    theory = Panel(
        "\n".join([
            "[bold]Сценарий:[/] secure boot authorization",
            "  user_token = [red]0x00[/]  (атакующий, НЕ авторизован)",
            "  secret_key = [green]0x50[/]  (правильный токен)",
            "",
            "[bold]Нормальный путь:[/]  A → B → D  ([green]DENY[/])",
            "[bold]Fault-атака:[/]     A ──⚡──► C  ([red]GRANT – взлом![/])",
            "",
            f"[bold]YACCA:[/]  END блока X: [cyan]xori t5, t5, M2_X[/]   → t5 = B_X",
            f"        START блока Y: [cyan]bne  t5, B_pred, error[/]",
            f"  После fault: t5 = B_A = [yellow]{B_A}[/]",
            f"  Block C ожидает B_B = [yellow]{B_B}[/]  →  {B_A} ≠ {B_B}  →  [red bold]ERROR![/]",
        ]),
        title="[bold cyan]Теория[/]", border_style="cyan", padding=(0, 2))
    console.print(theory)
    console.print()

    BLOCK_STYLES = {
        'A': ('blue', 'Block A'),
        'B': ('yellow', 'Block B'),
        'C': ('red', 'Block C [ЦЕЛЬ]'),
        'D': ('green', 'Block D'),
        'E': ('magenta', 'Error Handler'),
    }

    for exp in datasets:
        style = "bold red" if exp['is_fault'] else "dim"
        console.rule(f"[{style}][{exp['num']}]  {exp['label']}[/]", style="dim")
        console.print()

        table = Table(box=rbox.SIMPLE_HEAD, header_style="bold dim",
                      padding=(0, 1))
        table.add_column("Шаг",  width=4,  justify="right", style="dim")
        table.add_column("PC",   width=12, style="cyan")
        table.add_column("Hex",  width=10)
        table.add_column("Дизассемблер", width=30)
        table.add_column("Блок",         width=22)
        table.add_column("Примечание",   width=26)

        prev_block = None
        for si, frame in enumerate(exp['frames'], 1):
            blk = frame['block']
            bstyle, bname = BLOCK_STYLES.get(blk, ('white', '?'))
            note = ''
            if frame['is_fault']:
                note = '[red bold]← FAULT[/]'
            elif blk == 'E':
                note = '[magenta]← CFE обнаружен[/]'
            elif 'ebreak' in frame['dis']:
                note = '[bold]← завершение[/]'

            block_label = f'[{bstyle}]{bname}[/]' if blk else ''
            prefix = '' if blk == prev_block else f'[{bstyle} bold]▶ [/]'
            table.add_row(
                str(si),
                f'[cyan]0x{frame["pc"]:08X}[/]',
                f'[dim]{frame["instr"]}[/]',
                f'[white]{frame["dis"]}[/]',
                f'{prefix}{block_label}',
                note,
                style='dim' if blk == prev_block else '',
            )
            prev_block = blk

        console.print(table)
        rs = 'green' if exp['color'] in (C['ok'],) else 'red'
        console.print(Align.center(
            f"Результат: [{rs} bold]{exp['text']}[/]  │  {len(exp['frames'])} шагов"))
        console.print()

    # Сводная таблица
    console.rule("[bold]Итоговая таблица[/]")
    summary = Table(box=rbox.ROUNDED, border_style="dim",
                    header_style="bold cyan", show_lines=True)
    summary.add_column("#",              width=3, justify="center")
    summary.add_column("Конфигурация",  width=28)
    summary.add_column("Результат",     width=26)
    summary.add_column("Безопасность",  width=14, justify="center")
    summary.add_column("Шаги",          width=5,  justify="right")

    icons = {
        C['ok']:  ('✅', 'green'),
        C['bad']: ('❌', 'red'),
    }
    for exp in datasets:
        icon, ic = icons.get(exp['color'], ('?', 'yellow'))
        summary.add_row(str(exp['num']), exp['label'],
                        f"[{ic}]{exp['text']}[/]",
                        f"[{ic}]{icon}[/]",
                        str(len(exp['frames'])))
    console.print(summary)

    np_steps = len(datasets[0]['frames'])
    ya_steps = len(datasets[2]['frames'])
    oh = (ya_steps - np_steps) / np_steps * 100
    console.print()
    console.print(Panel(
        f"Execution overhead:  +{ya_steps - np_steps} шагов  "
        f"([yellow]{oh:.0f}%[/])  ({np_steps} → {ya_steps})\n"
        "Соответствует данным диссертации Vankeirsbilck §4.2: ~100–150%.",
        title="[bold]YACCA Overhead[/]", border_style="yellow", padding=(0, 2)))
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  Точка входа
# ══════════════════════════════════════════════════════════════════════════════

def main():
    args = set(sys.argv[1:])
    do_anim   = '--static' not in args and '--term' not in args
    do_static = '--static' in args or '--all' in args
    do_term   = '--term'   in args or '--all' in args
    do_anim   = do_anim or '--all' in args

    print("Запуск симуляций...")
    datasets = prepare_experiments()
    print(f"  4 эксперимента завершены.\n")

    if do_term:
        run_terminal(datasets)

    if do_static:
        print("Генерация статичной PNG...")
        run_static(datasets)

    if do_anim:
        print("Генерация анимации GIF...")
        run_animation(datasets)


if __name__ == '__main__':
    main()
