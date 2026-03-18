/*
 * link.ld – Linker script for biRISC-V TCM (128 KB)
 *
 * Memory map:
 *   0x80000000 .. 0x8001FFFF  TCM (code + data)
 *   0x80010000                RESULT_ADDR (data section, mid-TCM)
 *
 * Reset vector is 0x80000000 (set in tb_top.v).
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    TCM (rwx) : ORIGIN = 0x80000000, LENGTH = 128K
}

SECTIONS
{
    . = 0x80000000;

    .text :
    {
        *(.text.startup)   /* startup first */
        *(.text*)
        . = ALIGN(4);
    } > TCM

    .rodata :
    {
        . = ALIGN(4);
        *(.rodata*)
        . = ALIGN(4);
    } > TCM

    /* Data section at 0x80010000 (mid-TCM) */
    . = 0x80010000;

    .data :
    {
        . = ALIGN(4);
        *(.data*)
        . = ALIGN(4);
    } > TCM

    .bss :
    {
        . = ALIGN(4);
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
    } > TCM

    /DISCARD/ : { *(.comment) *(.eh_frame) }
}
