#!/bin/sh -ex

mkdir build-tun
cd build-tun
cmake -G Ninja \
-DCMAKE_C_COMPILER=clang \
-DCMAKE_LINKER_TYPE=LLD \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=1 \
-DENABLE_ASAN=0 \
-DENABLE_UBSAN=0 \
-DENABLE_TSAN=0 \
../vole/tun
ninja
