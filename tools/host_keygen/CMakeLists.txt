# Standalone host-native build. Deliberately NOT added as a subdirectory of
# the top-level Pinata/CMakeLists.txt: that project always cross-compiles
# for ARM (see Pinata/*.toolchain.cmake), and this tool must build with the
# host's own compiler instead. Build it separately, e.g.:
#
#   cmake -S Pinata/tools/host_keygen -B Pinata/tools/host_keygen/build
#   cmake --build Pinata/tools/host_keygen/build
#
cmake_minimum_required(VERSION 3.16)
project(falcon_host_keygen LANGUAGES C)

add_executable(host_keygen
    main.c
    fndsa/kgen.c
    fndsa/kgen_fxp.c
    fndsa/kgen_gauss.c
    fndsa/kgen_mp31.c
    fndsa/kgen_ntru.c
    fndsa/kgen_poly.c
    fndsa/kgen_zint31.c
    fndsa/mq.c
    fndsa/sha3.c
    fndsa/sysrng.c
    fndsa/codec.c
    fndsa/util.c
)
target_include_directories(host_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(host_keygen PROPERTIES C_STANDARD 11)

# fndsa/kgen.c's x86 fast path (see fndsa/inner.h: TARGET_AVX2) marks
# individual functions __attribute__((target("avx2"))) and passes __m256i
# arguments by value; dispatch to it happens at runtime via has_avx2()/cpuid.
# On MinGW-w64/GCC 13 this crashes (SIGSEGV on entry to the first AVX2
# function, confirmed via gdb) - a known-flavor toolchain/ABI mismatch
# handling 256-bit vector-by-value arguments under the Windows x64 calling
# convention, not something worth chasing for a one-off host dev tool.
# FNDSA_AVX2=0 disables that path entirely and falls back to the plain
# portable-C implementation, which is what the ARM firmware itself uses
# anyway (Cortex-M4 has no AVX2). Keygen only runs a handful of times, so
# the lack of AVX2 speedup is irrelevant here.
target_compile_definitions(host_keygen PRIVATE FNDSA_AVX2=0)
