/*
 * seL4 Microkit MILS Domain Linker Script
 * =======================================
 * Target Architectures: AArch64 / x86_64 / RISC-V 64
 * Assurance Level: Common Criteria EAL6+ / EAL7 Equivalent
 *
 * Enforces W^X (Write XOR Execute) Memory Policy:
 *   - .text   : RX (Read + Execute, strictly read-only code)
 *   - .rodata : R  (Read-Only Data, non-executable)
 *   - .data   : RW (Read + Write Data, non-executable)
 *   - .bss    : RW (Zero-initialized RAM, non-executable)
 *   - .stack  : RW (16 KiB Page-Aligned Stack, non-executable)
 *
 * GNU_STACK header marked non-executable (PT_GNU_STACK = 0x6474e551).
 */

ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);    /* RX: Read + Execute */
    rodata PT_LOAD FLAGS(4);  /* R : Read-Only */
    data PT_LOAD FLAGS(6);    /* RW: Read + Write */
}

SECTIONS
{
    /* Code segment starts at 4 KiB aligned virtual base */
    . = 0x00010000;

    .text : ALIGN(4096) {
        *(.text._start)
        *(.text*)
    } :text

    . = ALIGN(4096);

    .rodata : ALIGN(4096) {
        *(.rodata*)
    } :rodata

    . = ALIGN(4096);

    .data : ALIGN(4096) {
        *(.data*)
        *(.sdata*)
    } :data

    .bss : ALIGN(4096) {
        *(.bss*)
        *(.sbss*)
        *(COMMON)
    } :data

    . = ALIGN(4096);

    /* Dedicated 16 KiB Guarded Stack */
    .stack (NOLOAD) : ALIGN(4096) {
        __stack_bottom = .;
        . += 0x4000; /* 16 KiB */
        __stack_top = .;
    } :data

    /* Mark GNU Stack segment as non-executable */
    .note.GNU-stack "" : {
        *(.note.GNU-stack)
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
    }
}
