cmake_minimum_required(VERSION 3.22)
project(freeze_daemon CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

add_compile_options(-Wall -Wextra -O2 -ffunction-sections -fdata-sections)

set(LIBBPF_DIR "${CMAKE_SOURCE_DIR}/prebuilt/libbpf" CACHE PATH "Path to libbpf installation")

add_custom_target(bpf
    COMMAND clang -target bpf -O2 -g -mcpu=v2
            -D__TARGET_ARCH_arm64
            -I${CMAKE_SOURCE_DIR}/src
            -c ${CMAKE_SOURCE_DIR}/src/platform/freeze_monitor.bpf.c
            -o ${CMAKE_BINARY_DIR}/freeze_monitor.bpf.o
    DEPENDS ${CMAKE_SOURCE_DIR}/src/platform/freeze_monitor.bpf.c
            ${CMAKE_SOURCE_DIR}/src/vmlinux.h
    COMMENT "Building eBPF program"
)

add_executable(freeze_daemon src/main.cpp)
add_dependencies(freeze_daemon bpf)

target_include_directories(freeze_daemon PRIVATE src)

target_link_options(freeze_daemon PRIVATE -Wl,--gc-sections -Wl,--strip-all -s)

set(LIBBPF_LIB "${LIBBPF_DIR}/lib/libbpf.a")
set(LIBBPF_INCLUDE "${LIBBPF_DIR}/include")

# libbpf.a 内部调用了 libelf 解析 ELF 段/符号表，以及 libelf 解压缩用的 zlib。
# 静态链接时这些符号不会自动带入，必须显式链接，否则会在链接阶段报
# undefined reference to `elf_begin` / `elf_end` / `inflate` 等符号。
# 这两个库由 CI 的 "Cross-compile libbpf for arm64-v8a" 步骤和 libbpf 一起
# 编译进同一个 prebuilt/libbpf/lib 目录。
set(LIBELF_LIB "${LIBBPF_DIR}/lib/libelf.a")
set(LIBZ_LIB   "${LIBBPF_DIR}/lib/libz.a")

if(NOT EXISTS "${LIBBPF_LIB}" OR NOT EXISTS "${LIBBPF_INCLUDE}/bpf/libbpf.h")
    message(FATAL_ERROR "libbpf not found at ${LIBBPF_DIR}. "
                        "Expected ${LIBBPF_LIB} and ${LIBBPF_INCLUDE}/bpf/libbpf.h")
endif()

if(NOT EXISTS "${LIBELF_LIB}")
    message(FATAL_ERROR "libelf not found at ${LIBELF_LIB}. "
                        "libbpf links against libelf; it must be built alongside libbpf.")
endif()

if(NOT EXISTS "${LIBZ_LIB}")
    message(FATAL_ERROR "libz not found at ${LIBZ_LIB}. "
                        "libelf links against zlib; it must be built alongside libbpf.")
endif()

target_include_directories(freeze_daemon PRIVATE ${LIBBPF_INCLUDE})

# 链接顺序有意义：静态链接器按从左到右单趟解析符号依赖，
# libbpf 依赖 libelf 的符号，libelf 依赖 libz 的符号，所以必须
# 严格按 libbpf -> libelf -> libz 的顺序排列。
target_link_libraries(freeze_daemon ${LIBBPF_LIB} ${LIBELF_LIB} ${LIBZ_LIB})

message(STATUS "freeze_daemon configured. libbpf: ${LIBBPF_LIB}, libelf: ${LIBELF_LIB}, libz: ${LIBZ_LIB}")