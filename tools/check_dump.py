#!/usr/bin/env python3
"""Verify that the user's own PPSA26344 dump + local build prerequisites are in place.

Usage: python tools/check_dump.py [--root PATH]
Exit code 0 = ready, 1 = something missing. Never copies or uploads anything.
"""
import argparse
import shutil
import sys
from pathlib import Path

REQUIRED_DUMP = [
    "PPSA26344/PPSA26344-app/eboot.bin",
    "PPSA26344/PPSA26344-app/ampr_emu.index",
    "PPSA26344/PPSA26344-app/cache_ps5/all_shaders.xpps",
    "PPSA26344/PPSA26344-app/sce_module/libc.prx",
    "PPSA26344/PPSA26344-app/fakelib/libSceAgc.sprx",
    "PPSA26344/PPSA26344-app/fakelib/libSceAgcDriver.sprx",
    "PPSA26344/PPSA26344-app/fakelib/libSceAmpr.sprx",
]
EXTRACTED = ["extracted_elf/eboot.elf"]
IN_REPO = ["docs/nid_resolution_table.json", "CMakeLists.txt", "src/main.cpp"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = ap.parse_args().root
    ok = True

    def check(label: str, rels: list[str], hint: str) -> None:
        nonlocal ok
        print(f"[{label}]")
        for rel in rels:
            good = (root / rel).exists()
            ok &= good
            print(f"  {'OK     ' if good else 'MISSING'} {rel}")
        if any(not (root / r).exists() for r in rels):
            print(f"  -> {hint}")

    check("repo files", IN_REPO, "run `git pull` / re-clone")
    check("your game dump (not in git)", REQUIRED_DUMP,
          "copy your own dump to <root>/PPSA26344/ (see docs/SETUP.md)")
    check("extracted ELFs (generated)", EXTRACTED,
          "python tools/unself.py <dump>/PPSA26344-app/eboot.bin extracted_elf/eboot.elf")

    print("[toolchain]")
    for tool in ("cmake", "ninja", "cl"):
        found = shutil.which(tool)
        print(f"  {'OK     ' if found else 'NOT IN PATH'} {tool}"
              + ("" if found else "  (open a VS 2022 x64 Native Tools prompt)"))
    print("\nREADY" if ok else "\nNOT READY")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
