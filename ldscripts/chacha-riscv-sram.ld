SECTION_DATA_PROLOGUE(.chacha_sram,,)
{
    . = ALIGN(4);
    *chacha-riscv.S.obj(.text .text.*)
    *(.chacha_wrap)
    . = ALIGN(4);
} GROUP_DATA_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)
