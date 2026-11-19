cmake_minimum_required(VERSION 3.22)
project(YoteiPort VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /EHsc /utf-8 /arch:AVX2)
endif()

add_executable(yotei_runtime
    src/main.cpp
    src/loader/elf_mapper.cpp
    src/hle/nid_registry.cpp
    src/kernel/memory.cpp
    src/kernel/filesystem.cpp
)

target_include_directories(yotei_runtime PRIVATE src)
