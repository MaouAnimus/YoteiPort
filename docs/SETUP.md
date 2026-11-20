# Setup on a new machine

This repo is **clean-room / BYOD**: it contains code and tooling only. You must supply
your own legitimate dump of `PPSA26344`. Never commit the dump, extracted ELFs or assets
(`.gitignore` already blocks them).

## What you need

| Item | In git? | Notes |
|---|---|---|
| Source, `tools/`, `docs/` (incl. `nid_resolution_table.json`) | yes | `git clone` |
| `PPSA26344/` dump (~200 GB) | **no** | copy to `<repo>/PPSA26344/` |
| `extracted_elf/*.elf` | no | regenerate (below) |
| `extracted_assets/` | no | regenerate with `tools/convert_assets.py` |
| `oo2core_9_win64.dll` | no | third-party, copy it yourself (only for asset tools) |
| `KytyPS5-Yotei/`, `PS5PKGTool*/` | no | optional reference tools, download separately |

Building/editing code needs only the repo + toolchain. **Running** the runtime needs the dump
(it reads `/app0` = `PPSA26344/PPSA26344-app`, `ampr_emu.index`, `all_shaders.xpps`).
Whether the full 200 GB is required has not been verified; the runtime only opens files the game requests.

## Steps (Windows x64)

1. Install VS 2022 Build Tools (C++ workload, CMake, Ninja) and Python 3.10+.
2. `git clone https://github.com/MaouAnimus/YoteiPort.git`
3. Copy your dump to `YoteiPort/PPSA26344/`.
4. Generate the ELF: `python tools/unself.py PPSA26344/PPSA26344-app/eboot.bin extracted_elf/eboot.elf`
   (other modules: repeat for `fakelib/*.sprx` and `sce_module/libc.prx`).
5. Check everything: `python tools/check_dump.py`
6. From an **x64 Native Tools Command Prompt**:
   `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release` then `ninja -C build`
7. Run: `build\yotei_runtime.exe`

The runtime finds the project root automatically (walks up from the exe looking for
`docs/nid_resolution_table.json`). Override with the `YOTEI_ROOT` environment variable.

## Known state

Experimental: the runtime boots the guest, spawns worker threads and can dispatch a translated
compute shader on the host GPU, but the game is not playable and the process can crash
non-deterministically. See `execution_plan.md` for status.
