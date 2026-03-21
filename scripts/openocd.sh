#!/bin/sh -ex

/w/openocd-esp32/bin/openocd -c 'set ESP_FLASH_SIZE 0; set ESP_RTOS none' -f board/esp32c6-builtin.cfg
