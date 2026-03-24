cmake_minimum_required(VERSION 3.20.0)

project(tun LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_library(LIBMNL mnl REQUIRED)
find_library(LIBSECCOMP seccomp REQUIRED)

option(ENABLE_ASAN  "Enable Address Sanitizer" OFF)
option(ENABLE_UBSAN "Enable Undefined Behavior Sanitizer" OFF)
option(ENABLE_TSAN  "Enable Thread Sanitizer" OFF)

set(BUILD_SHARED_LIBS       OFF CACHE BOOL "" FORCE)
set(WOLFSSL_TLS13            ON CACHE BOOL "" FORCE)
set(WOLFSSL_DTLS             ON CACHE BOOL "" FORCE)
set(WOLFSSL_DTLS13           ON CACHE BOOL "" FORCE)
set(WOLFSSL_HRR_COOKIE       ON CACHE BOOL "" FORCE)
set(WOLFSSL_PSK              ON CACHE BOOL "" FORCE)
set(WOLFSSL_DEBUG           OFF CACHE BOOL "" FORCE)
set(WOLFSSL_RSA             OFF CACHE BOOL "" FORCE)
set(WOLFSSL_DH              OFF CACHE BOOL "" FORCE)
set(WOLFSSL_EH              OFF CACHE BOOL "" FORCE)
set(WOLFSSL_EXTENDED_MASTER OFF CACHE BOOL "" FORCE)
set(WOLFSSL_ENC_THEN_MAC    OFF CACHE BOOL "" FORCE)
set(WOLFSSL_PKCS12          OFF CACHE BOOL "" FORCE)
set(WOLFSSL_OLD_NAMES       OFF CACHE BOOL "" FORCE)
set(WOLFSSL_AESCCM           ON CACHE BOOL "" FORCE)
set(WOLFSSL_CURVE25519       ON CACHE BOOL "" FORCE)
set(WOLFSSL_ED25519          ON CACHE BOOL "" FORCE)
set(WOLFSSL_EXAMPLES        OFF CACHE BOOL "" FORCE)
set(WOLFSSL_CRYPT_TESTS     OFF CACHE BOOL "" FORCE)
set(WOLFSSL_BASE64_ENCODE    ON CACHE BOOL "" FORCE)

# For pure DTLS 1.3
# set(WOLFSSL_TLSV12          OFF CACHE BOOL "" FORCE)
# set(WOLFSSL_ECC             OFF CACHE BOOL "" FORCE)
# set(WOLFSSL_SHA             OFF CACHE BOOL "" FORCE)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(WOLFSSL_DEBUG ON CACHE BOOL "" FORCE)
endif()

if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

if(ENABLE_TSAN)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION" _version_lines)
foreach(_line ${_version_lines})
    if(_line MATCHES "^([A-Z_]+) = ([0-9]+)$")
        set(${CMAKE_MATCH_1} ${CMAKE_MATCH_2})
    endif()
endforeach()
execute_process(
    COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse --short=12 HEAD
    OUTPUT_VARIABLE GIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT GIT_HASH)
    set(GIT_HASH "unknown")
endif()
configure_file(version.h.in version.h)

add_compile_definitions(WOLFSSL_GETRANDOM WOLFSSL_MAX_MTU=1472 HAVE_NULL_CIPHER)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../wolfssl wolfssl)

add_library(tomlc17 STATIC ${CMAKE_CURRENT_SOURCE_DIR}/../../tomlc17/src/tomlc17.c)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../tomlc17/src)

add_executable(tun tun.c)
target_include_directories(tun PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_options(tun PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(tun PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED ON)
target_link_libraries(tun PRIVATE tomlc17 ${LIBMNL} ${LIBSECCOMP} wolfssl)
