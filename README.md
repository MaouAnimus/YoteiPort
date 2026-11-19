# YoteiPort — Experimental Native PC Runtime & Reverse Engineering Suite for *Ghost of Yōtei*

> **Clean-Room Notice (BYOD — Bring Your Own Dump):**  
> This repository contains **zero copyrighted game code, zero Sony firmware modules, and zero proprietary assets**. Just like community preservation/recompilation projects for *Bloodborne*, *God of War III*, or *Zelda64Recomp*, you must provide your own legally dumped copy of **Ghost of Yōtei (`PPSA26344`, version `02.002.000`)** from your PlayStation 5 console.

---

## Overview

**YoteiPort** is an experimental native x86-64 Windows execution layer, High-Level Emulation (HLE) bridge, and proprietary asset/shader extraction toolkit for Sucker Punch Productions' **Ghost of Yōtei** (`ne_ps5_ship.elf`, Title ID `PPSA26344`).

Because the PlayStation 5 (Prospero) shares an **x86-64 (AMD Zen 2)** instruction set with modern PCs, the game's compiled CPU code (`eboot.bin`, 25.07 MB `.text` segment) can execute **natively on Windows x64 without CPU instruction emulation**, provided that:
1. The decrypted PS5 `ET_SCE_DYNEXEC` (`0xfe10`) SELF image is unpacked and mapped into a 64-bit guest virtual address space (`0x800000000`), with all **215,286** internal `R_X86_64_RELATIVE` relocations and **824** GOT/PLT slots resolved.
2. Calls from the game's **System V AMD64 ABI** (`rdi, rsi, rdx, rcx, r8, r9`) to Sony's 51 dynamic libraries (**715 imported NIDs**) are bridged via dynamically generated machine-code trampolines to **Microsoft x64 ABI** HLE handlers (`libkernel`, `libSceAgc`, `libSceAgcDriver`, `libSceAmpr`, `libc`, etc.).
3. Sucker Punch's custom asset containers (`AMPRIDX3`, `KCAP / .xpps`, `XTBS / .sps`, `SMBS / .xmesh`, `FNMS / .texmeshman`) and **AGC / RDNA2** GPU command streams are translated to host I/O and Vulkan 1.3.

---

## Repository Structure

```text
YoteiPort/
├── CMakeLists.txt                       # C++20 CMake build configuration (MSVC / Clang-CL + Ninja)
├── setup_and_run.bat                    # One-click BYOD setup, ELF extraction, C++ build & execution
├── LICENSE                              # MIT License
├── src/
│   ├── main.cpp                         # Native x86-64 guest execution harness & VEH diagnostics
│   ├── loader/
│   │   ├── elf_mapper.h                 # ELF64 Program Header, PT_DYNAMIC & RELA parser
│   │   └── elf_mapper.cpp               # VirtualAlloc guest mapper & 216,110 relocation engine
│   └── hle/
│       ├── nid_registry.h               # 715 NID symbol registry & GOT patcher
│       └── nid_registry.cpp             # SysV AMD64 -> MS x64 machine-code trampoline generator & HLE hooks
├── tools/
│   ├── unself.py                        # Decrypted PS5 Fake-Signed SELF / SPRX / PRX -> ELF64 converter
│   ├── inspect_yotei.py                 # Static analyzer for eboot.elf PT_DYNAMIC & ampr_emu.index
│   ├── resolve_nids.py                  # Resolves 715 NIDs via Sony SHA-1 salt & HLE tables + emits Ghidra script
│   ├── convert_assets.py                # Converts .xmesh -> .obj, .sps -> .dds, and extracts .xpps AGC shaders
│   ├── noesis_yotei_sps_xmesh.py        # Noesis Python plugin for direct 3D mesh (.xmesh) & texture (.sps) preview
│   ├── ampr_index.ksy                   # Kaitai Struct specification for ampr_emu.index (AMPRIDX3)
│   ├── kcap_xpps.ksy                    # Kaitai Struct specification for .xpps packages (KCAP v30.41)
│   ├── xtbs_sps.ksy                     # Kaitai Struct specification for .sps textures (XTBS v1.30)
│   ├── smbs_xmesh.ksy                   # Kaitai Struct specification for .xmesh 3D meshes (SMBS v1.0.2)
│   └── ghidra/
│       └── apply_yotei_nids.py          # Ghidra post-analysis script labeling all 824 GOT symbol slots
└── docs/
    ├── initial_inspection.json          # Complete static inventory of eboot.elf & 105,803 indexed assets
    └── nid_resolution_table.json        # Full resolution table of all 715 imported PS5 NIDs & GOT addresses
```

---

## Quick Start (Bring Your Own Dump)

### Prerequisites
- **Windows 10 / 11 (64-bit)** with an AVX2-capable CPU.
- **Visual Studio 2022** (or Build Tools 2022) with the *Desktop development with C++* workload (`cl.exe` / `clang-cl.exe`, `CMake`, `Ninja`).
- **Python 3.10+** (for `tools/unself.py` and asset extractors).
- A legally obtained, decrypted dump of **Ghost of Yōtei (`PPSA26344` v02.002.000)** (`PPSA26344-app/` folder containing `eboot.bin`, `ampr_emu.index`, `fakelib/`, and `cache_ps5/`).

### 1. One-Command Setup, Build & Native Execution Probe
Pass the path to your `PPSA26344-app` dump directory (or place it at `PPSA26344\PPSA26344-app` next to this repository) and run:

```bat
setup_and_run.bat "C:\Path\To\Your\PPSA26344-app"
```

This script automatically:
1. Unpacks `eboot.bin` and `fakelib/*.sprx` into clean ELF64 binaries under `extracted_elf/` (git-ignored).
2. Compiles `yotei_runtime.exe` in Release mode using CMake + Ninja.
3. Maps `eboot.elf` at `0x800000000`, applies all `215,286` internal relocations + `824` GOT trampolines, and natively executes the engine's early memory pool & virtual mount-point initialization (`sub_cd85f0`), logging all 96 HLE calls across the SysV-to-MSx64 bridge (`PthreadMutexInit`, `NetCtlGetInfo`, `KernelGetDirectMemorySize`, `KernelConfiguredFlexibleMemorySize`, `KernelAllocateDirectMemory`, `KernelBatchMap`, `/app0`, `/cache_ps5`, `/host/%ART%`).

### 2. Extracting 3D Meshes (`.xmesh`), Textures (`.sps`), and Shaders (`.xpps`)
Use `tools/convert_assets.py` against any file in your dump's `cache_ps5/` folder:

```bat
:: Convert a 3D mesh (.xmesh -> Wavefront .obj for Blender)
python tools\convert_assets.py --xmesh "PPSA26344\PPSA26344-app\cache_ps5\meshes\action_katana.xmesh"

:: Convert a texture (.sps -> DirectX 10 .dds for Noesis / RenderDoc)
python tools\convert_assets.py --sps "PPSA26344\PPSA26344-app\cache_ps5\bitmaps\debugfont.png.0.sps"

:: Inspect & extract AGC RDNA2 shader headers from a KCAP (.xpps) package
python tools\convert_assets.py --xpps "PPSA26344\PPSA26344-app\cache_ps5\all_shaders.xpps"
```

To preview `.sps` textures and `.xmesh` 3D models directly in **Noesis**, copy `tools/noesis_yotei_sps_xmesh.py` into your Noesis `plugins/python/` folder.

### 3. Reverse Engineering in Ghidra
1. Import `extracted_elf/eboot_et_dyn.elf` (generated with `python tools/unself.py eboot.bin extracted_elf/eboot_et_dyn.elf --patch-et-dyn`) into **Ghidra 12.1+**.
2. Run `tools/ghidra/apply_yotei_nids.py` from Ghidra's Script Manager to automatically label all **824 GOT entries** with their resolved Sony Prospero function names (`libSceAgc__Gen5_AgcInit`, `libkernel__Memory_KernelAllocateDirectMemory`, etc.).

---

## Disclaimer

*Ghost of Yōtei*, *PlayStation*, *PS5*, and *Prospero* are registered trademarks of Sony Interactive Entertainment Inc. and Sucker Punch Productions. This project is an independent, non-commercial technical research and interoperability effort and is neither affiliated with nor endorsed by Sony Interactive Entertainment or Sucker Punch Productions.
