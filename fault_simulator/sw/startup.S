/* startup.S – Minimal RISC-V bare-metal startup for biRISC-V TCM
 *
 * Sets up the stack pointer and jumps to main.
 * Reset vector: 0x80000000 (configured in biRISC-V testbench).
 */

    .section .text.startup
    .global  _start
    .type    _start, @function

_start:
    /* Stack pointer = top of TCM (128 KB above reset vector) */
    lui  sp, 0x80020        /* sp = 0x80020000 */

    /* Call application */
    call main

    /* If main returns – halt */
_hang:
    j _hang

    .size _start, . - _start
