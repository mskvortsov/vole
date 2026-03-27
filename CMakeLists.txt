cmake_minimum_required(VERSION 3.20.0)

set(ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../wolfssl)

if(BOARD MATCHES "esp32")
    list(APPEND EXTRA_CONF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/boards/esp32-common.conf)
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(vole)

zephyr_get_include_directories_for_lang(       C includes)
zephyr_get_system_include_directories_for_lang(C system_includes)
zephyr_get_compile_definitions_for_lang(       C definitions)
zephyr_get_compile_options_for_lang(           C options)

if(DEFINED CMAKE_C_COMPILER_TARGET)
    set(target_flag "--target=${CMAKE_C_COMPILER_TARGET}")
endif()

add_library(tomlc17 STATIC ${WEST_TOPDIR}/tomlc17/src/tomlc17.c)
target_compile_options(tomlc17 PRIVATE ${target_flag} ${includes} ${definitions}
    ${options} ${system_includes})
include_directories(${WEST_TOPDIR}/tomlc17/src)

file(GLOB app_sources src/main.c src/dtls.c src/crypto.c src/bench.c src/npf.c
    src/config.c src/status.c src/wifi.c src/aqm.c src/telemetry.c)
if(CONFIG_VOLE_LAN)
    list(APPEND app_sources src/ra.c src/dhcp4.c)
endif()
target_sources(app PRIVATE ${app_sources})
target_compile_options(app PRIVATE -Wall -Wextra)
target_link_libraries(app PUBLIC tomlc17)

zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/ip)

if(CONFIG_RISCV)
    set(chacha_S ${CMAKE_CURRENT_BINARY_DIR}/chacha-riscv.S)
    add_custom_command(
        OUTPUT  ${chacha_S}
        COMMAND perl ${WEST_TOPDIR}/cryptogams/riscv/chacha-riscv.pl > ${chacha_S}
        DEPENDS ${WEST_TOPDIR}/cryptogams/riscv/chacha-riscv.pl
        COMMENT "Generating chacha-riscv.S from cryptogams"
    )
    target_sources(app PRIVATE ${chacha_S})
    zephyr_ld_options(-Wl,--wrap=wc_Chacha_Process)
    zephyr_linker_sources(DATA_SECTIONS ldscripts/chacha-riscv-sram.ld)
endif()

if(CONFIG_SOC_SERIES_ESP32S3)
    zephyr_linker_sources(DATA_SECTIONS ldscripts/sections-esp32s3-sram2.ld)
endif()

zephyr_linker_sources(SECTIONS ldscripts/sections-rom.ld)
zephyr_linker_section(
    NAME http_resource_desc_http_service
    KVMA RAM_REGION GROUP RODATA_REGION)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)
generate_inc_file_for_target(app www/dist/index.html
    ${gen_dir}/index.html.gz.inc --gzip)
generate_inc_file_for_target(app default.toml ${gen_dir}/default.toml.inc)
