# YACCA Fault Injection Demo for biRISC-V

Демонстрация fault-атаки на управляющий поток программы (Control Flow Error) и защиты с помощью техники **YACCA** (*Yet Another Control-flow Checking using Assertions*) на процессоре biRISC-V (RISC-V RV32I).

> **Источник:** Vankeirsbilck J., *"Advancing Control Flow Error Detection Techniques for Embedded Software using Automated Implementation and Fault Injection"*, KU Leuven, 2020 — §2.3.2 YACCA.
>
> **Целевая платформа:** [biRISC-V](https://github.com/YarosLove91/biriscv/tree/periphery) — суперскалярный двухпоточный (dual-issue) RISC-V процессор.

---

## Быстрый старт (только Python, без инструментов)

```bash
cd fault_sim
python3 run_demo.py            # запустить все 4 эксперимента
python3 run_demo.py --trace    # с трассировкой инструкций
python3 run_demo.py --listing  # с листингом ассемблера
```

Зависимости: **Python 3.9+**, сторонние библиотеки не нужны.

---

## Теоретическая база

### Что такое Control Flow Error (CFE)

CFE — нарушение порядка выполнения инструкций, вызванное внешним физическим воздействием:

| Тип атаки | Механизм | Эффект на процессор |
|---|---|---|
| **Clock glitch** | Изменение периода тактового сигнала | Пропуск инструкции, неверный PC |
| **Voltage glitch** | Кратковременное изменение VCC | Битфлип в регистрах/памяти |
| **EM pulse** | Электромагнитное воздействие | Битфлип в программном счётчике |

Последствие: программа «перепрыгивает» на другой базовый блок, нарушая CFG (Control Flow Graph). Это позволяет атакующему обойти проверки безопасности.

### Классификация CFE (по Vankeirsbilck §2.2)

```
CFG:  Block A ──→ Block B ──→ Block C
                     └──→ Block D

1. Inter-block CFE:  прыжок между разными блоками (A → C, минуя B)
2. Intra-block CFE:  прыжок внутри блока (середина B → середина B)
3. Out-of-CFG CFE:  прыжок за пределы программы
```

YACCA обнаруживает **inter-block CFE**.

---

## Сценарий демонстрации

**Задача:** устройство проверяет токен авторизации перед выполнением привилегированной операции.

```
user_token  = 0x00  (атакующий, не авторизован)
secret_key  = 0x50  (правильный токен)
```

### Control Flow Graph программы

```
  ┌──────────────────────────────────────────┐
  │  Block A  – Инициализация                │
  │  t0 = user_token = 0  (не авторизован)   │
  │  t1 = secret_key  = 0x50                 │
  └──────────────────┬───────────────────────┘
                     │  j block_b
                     │  ↑
                  FAULT: заменить на j block_c (пропустить проверку!)
                     │
  ┌──────────────────▼───────────────────────┐
  │  Block B  – Проверка авторизации         │
  │  bne t0, t1, block_d  (если ≠ → отказ)  │
  └────────┬──────────────────────┬──────────┘
   (совпад.)│                      │ (не совпад.)
  ┌─────────▼───────────┐  ┌──────▼──────────────┐
  │  Block C  – GRANT   │  │  Block D  – DENY     │
  │  a0 = 1             │  │  a0 = 0              │
  │  ← ЦЕЛЬ АТАКИ       │  │  ← нормальный путь  │
  └─────────────────────┘  └─────────────────────┘
```

**Нормальный путь:** A → B → D (токен неверный → отказ)
**Fault-атака:** A → C (минуя Block B → несанкционированный доступ!)

---

## YACCA: механизм защиты

### Принцип работы (YACCA_CMP variant)

Каждому базовому блоку назначается уникальная **сигнатура** (compile-time константа). Регистр `t5` хранит **run-time идентификатор** последнего выполненного блока.

```
В КОНЦЕ блока X:    xori t5, t5, M2_X    →  t5 становится равным B_X
В НАЧАЛЕ блока Y:   addi t4, x0, B_pred
                    bne  t5, t4, error   →  t5 ≠ B_pred → CFE обнаружен!
```

Где `M2_X = B_pred_X XOR B_X` — compile-time константа, уникальная для каждого блока.

### Compile-time сигнатуры для данного примера

| Блок | Сигнатура (B) | Предшественник | M2 = B_pred XOR B |
|------|:---:|---|:---:|
| A    | 5  | начало программы (1) | 4  |
| B    | 7  | A (5) | 2  |
| C    | 11 | B (7) | 12 |
| D    | 13 | B (7) | 10 |

### Детекция атаки (Experiment 4)

```
Нормальный путь A→B→D:
  После A:  t5 = 1 XOR 4 = 5  = B_A ✓
  В нач. B: bne t5(5), t4(5)  → не прыгаем (OK)
  После B:  t5 = 5 XOR 2 = 7  = B_B ✓
  В нач. D: bne t5(7), t4(7)  → не прыгаем (OK)

Fault-атака A→C (fault заменяет j block_b → j block_c):
  После A:  t5 = 1 XOR 4 = 5  = B_A
  В нач. C: addi t4, x0, 7  ← ожидаем B_B = 7
             bne t5(5), t4(7) → 5 ≠ 7 → ПРЫЖОК В error_handler!
  a0 = -1 (0xFFFFFFFF) → CFE DETECTED
```

---

## Результаты экспериментов

| # | Конфигурация | a0 | Итог |
|:---:|---|:---:|---|
| 1 | Без защиты, без атаки | 0 | ACCESS DENIED ✅ |
| **2** | **Без защиты, FAULT** | **1** | **ACCESS GRANTED ❌ (взлом!)** |
| 3 | YACCA, без атаки | 0 | ACCESS DENIED ✅ |
| **4** | **YACCA, FAULT** | **-1** | **CFE DETECTED 🛡️ (атака остановлена)** |

### YACCA Overhead

| Метрика | Без защиты | YACCA | Overhead |
|---|:---:|:---:|:---:|
| Инструкций (code size) | 9 | 20 | +122% |
| Шагов выполнения (время) | 6 | 13 | +117% |

> Overhead соответствует данным из диссертации Vankeirsbilck (Таблица 4.4): YACCA имеет более высокий overhead по сравнению с CFCSS, но обеспечивает хорошее покрытие inter-block CFE.

---

## Структура проекта

```
fault_simulator/
├── run_demo.py           # Главный скрипт эксперимента
├── riscv_sim.py          # RV32I симулятор и энкодер инструкций
├── programs.py           # Программы (unprotected + YACCA), fault injection
├── setup.sh              # Установка зависимостей, клонирование biRISC-V
├── sw/
│   ├── auth_noprotect.S  # RISC-V asm: без защиты
│   ├── auth_yacca.S      # RISC-V asm: с YACCA_CMP
│   ├── startup.S         # Стартовый код (инициализация стека)
│   ├── link.ld           # Линкер-скрипт для biRISC-V TCM
│   └── Makefile          # Сборка бинарников
└── tb/
    ├── tb_fault_inject.v # Verilog testbench с инъекцией ошибок
    └── Makefile          # RTL симуляция (Icarus Verilog)
```

---

## RTL-симуляция на biRISC-V

Для симуляции на настоящем RTL процессора нужны инструменты.

### Установка (macOS)

```bash
brew install icarus-verilog
brew install riscv-gnu-toolchain
```

### Установка (Ubuntu/Debian)

```bash
sudo apt install iverilog
sudo apt install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu
```

### Запуск

```bash
# 1. Клонировать biRISC-V и настроить среду
./setup.sh

# 2. Собрать RISC-V бинарники
cd sw && make

# 3. Запустить все 4 симуляции на Icarus Verilog
cd ../tb && make
```

Результат в консоли (пример для эксперимента 4):
```
[TB] *** FAULT INJECTION at cycle 10 ***
[TB]     Target addr:   0x80000010  (word 2, half 0)
[TB]     Original instr: 0040006F  (j block_b)
[TB]     Fault instr:    0180006F  (j block_c)

[TB] ═══════════════════════════════════════════════════
[TB]  RESULT WRITE detected at cycle 47
[TB]  Address : 0x80010000
[TB]  Value   : 0xFFFFFFFF
[TB]  *** CFE DETECTED – ATTACK STOPPED by YACCA! ***
[TB] ═══════════════════════════════════════════════════
```

### Параметры testbench (`tb_fault_inject.v`)

| Параметр | По умолчанию | Описание |
|---|---|---|
| `TCM_BIN` | `auth_yacca.bin` | Путь к бинарнику программы |
| `FAULT_INJECT` | `0` | `1` = инъекция активна |
| `FAULT_ADDR` | `0x80000010` | Адрес инструкции для замены |
| `FAULT_INSTR` | `0x0180006F` | Новая инструкция (JAL x0, +24) |
| `FAULT_CYCLE` | `10` | Такт активации инъекции |
| `RESULT_ADDR` | `0x80010000` | Адрес мониторинга результата |

### Карта памяти biRISC-V

```
0x80000000  Начало TCM (reset vector), код программы
0x80010000  RESULT_ADDR — куда программа пишет результат
0x80020000  Вершина стека (128 KB от начала TCM)
```

---

## Fault Injection: технические детали

### Как работает инъекция в testbench

TCM (Tightly Coupled Memory) biRISC-V индексируется по формуле:

```
word_index = addr[16:3]      // 14-битный адрес 64-битного слова
half       = addr[2]          // 0 = нижние 32 бит, 1 = верхние 32 бит
```

В нужный такт testbench записывает в `u_mem.u_ram.ram[word_index]` новую инструкцию:

```verilog
if (fault_half == 0)
    u_mem.u_ram.ram[fault_word_idx][31:0]  = FAULT_INSTR_P;
else
    u_mem.u_ram.ram[fault_word_idx][63:32] = FAULT_INSTR_P;
```

### Кодирование JAL-инструкции (замена для fault)

`j block_c` = `jal x0, offset`:

```
Unprotected: fault_pc=0x80000008, target=0x80000014, offset=+12
  → JAL x0, +12 = 0x00C0006F

YACCA:       fault_pc=0x80000010, target=0x80000028, offset=+24
  → JAL x0, +24 = 0x0180006F
```

---

## Компоненты Python-симулятора

### `riscv_sim.py`

- **Энкодеры**: `enc_addi`, `enc_xori`, `enc_lui`, `enc_jal`, `enc_bne`, `enc_beq`, `enc_ebreak`
- **Дизассемблер**: `disasm(instr, pc)` — текстовое представление инструкции
- **`RV32CPU`** — симулятор с трассировкой; поддерживает ADDI, XORI, LUI, AUIPC, JAL, ветвления, LOAD/STORE, R-type

### `programs.py`

- `make_noprotect()` — программа без YACCA
- `make_yacca()` — программа с YACCA_CMP
- `inject_fault(memory, fault_pc, target_pc)` — патч памяти: заменяет инструкцию на JAL к цели атаки

---

## Ограничения YACCA и направления улучшений

| Ограничение | Описание |
|---|---|
| **Только inter-block CFE** | Intra-block атаки (внутри блока) не обнаруживаются — нужен RSCFC или SIED |
| **Data flow errors** | Битфлипы в данных (а не в PC/IR) не детектируются YACCA |
| **Overhead** | ~120% по коду и времени — CFCSS или RACFED дают меньший overhead |
| **Маскировка** | Некоторые CFE маскируются при определённых CFG-топологиях (guideline 3 из диссертации) |

Для производственного применения рекомендуется **RACFED** (Random Additive Control Flow Error Detection) — метод из той же диссертации с улучшенным соотношением overhead/coverage.

---

## Ссылки

- Vankeirsbilck J. et al., *"YACCA: Yet Another Control-flow Checking using Assertions"*, 2015
- Goloubeva O. et al., *"Software-Implemented Hardware Fault Tolerance"*, Springer, 2006
- biRISC-V: https://github.com/YarosLove91/biriscv/tree/periphery
- RISC-V ISA Spec: https://riscv.org/technical/specifications/
