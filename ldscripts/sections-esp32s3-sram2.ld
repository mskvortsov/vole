#include <zephyr/devicetree.h>

.sram2 DT_REG_ADDR(DT_NODELABEL(sram2)) (NOLOAD) :
{
    . = ALIGN(8);
    KEEP(*libapp.a:dtls.c.obj(.noinit.*))

    . = ALIGN(8);
    KEEP(*liblib__libc__common.a:malloc.c.obj(.noinit.*))
}
