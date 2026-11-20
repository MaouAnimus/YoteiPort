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
    src/hle/ampr_hle.cpp
    src/kernel/memory.cpp
    src/kernel/filesystem.cpp
    src/kernel/threads.cpp
    src/graphics/pm4_decoder.cpp
    src/graphics/rdna2_shader.cpp
    src/graphics/vk_backend.cpp
    src/graphics/video_out_hle.cpp
)

target_include_directories(yotei_runtime PRIVATE src)

if(MSVC)
    # Explicitly add Windows SDK and UCRT include paths (vcvars may not set them up in BuildTools)
    # Windows SDK 10.0.26100.0
    target_include_directories(yotei_runtime PRIVATE
        "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/ucrt"
        "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um"
        "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/shared"
    )

    # MSVC CRT headers
    target_include_directories(yotei_runtime PRIVATE
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/include"
    )

    # Windows SDK library paths for linking
    target_link_directories(yotei_runtime PRIVATE
        "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/um/x64"
        "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/ucrt/x64"
    )

    # MSVC CRT library path
    target_link_directories(yotei_runtime PRIVATE
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/lib/x64"
    )
endif()
