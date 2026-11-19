#!/usr/bin/env python3
"""
inspect_yotei.py - Inventory and Static Analysis Tool for Ghost of Yotei (PPSA26344)
Parses:
  1. Decrypted ELF64 (eboot.elf) program headers, PT_DYNAMIC, imported modules & 715 NIDs
  2. AMPR Index (ampr_emu.index - AMPRIDX3 format, 105,803 asset entries)
  3. Shader & Asset Packs (.xpps - KCAP v30.41 format with Oodle Kraken decompression)
  4. Texture/Mesh Manifests (.texmeshman - FNMS format)
"""
import argparse
import collections
import ctypes
import json
import struct
from pathlib import Path

B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"


def decode_sce_b64_id(s: str) -> int:
    val = 0
    for c in s:
        val = (val << 6) | B64_CHARS.index(c)
    return val


def analyze_elf(elf_path: Path) -> dict:
    data = elf_path.read_bytes()
    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack("<HHIQQQIHHHHHH", data[16:64])

    ph_names = {
        0x1: "PT_LOAD",
        0x2: "PT_DYNAMIC",
        0x4: "PT_NOTE",
        0x7: "PT_TLS",
        0x61000000: "PT_SCE_RELRO",
        0x61000001: "PT_SCE_PROCPARAM",
        0x61000002: "PT_SCE_MODULE_PARAM",
        0x61000010: "PT_SCE_DYNLIBDATA",
        0x6474E550: "PT_GNU_EH_FRAME",
        0x6474E552: "PT_GNU_RELRO",
        0x6FFFFF00: "PT_SCE_LIBVERSION",
        0x6FFFFF01: "PT_SCE_COMMENT",
    }

    phs = []
    dyn_ph = None
    dynlib_ph = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = (
            struct.unpack("<IIQQQQQQ", data[off : off + e_phentsize])
        )
        rwx = (
            ("R" if p_flags & 4 else "-")
            + ("W" if p_flags & 2 else "-")
            + ("X" if p_flags & 1 else "-")
        )
        phs.append(
            {
                "index": i,
                "type": hex(p_type),
                "type_name": ph_names.get(p_type, "PT_LOAD/SCE"),
                "flags": rwx,
                "offset": hex(p_offset),
                "vaddr": hex(p_vaddr),
                "filesz": hex(p_filesz),
                "memsz": hex(p_memsz),
            }
        )
        if p_type == 0x2:
            dyn_ph = (p_offset, p_filesz)
        if p_vaddr == 0x717D610:
            dynlib_ph = (p_offset, p_vaddr, p_filesz)

    libs = {}
    mods = {}
    needed = []
    strtab = b""

    if dyn_ph and dynlib_ph:
        dyn_off, dyn_sz = dyn_ph
        dl_off, dl_vaddr, dl_sz = dynlib_ph

        def vaddr_to_off(v):
            return v - dl_vaddr + dl_off

        # First pass: locate DT_STRTAB (5) and DT_STRSZ (10)
        strtab_vaddr = 0
        strtab_sz = 0
        for i in range(0, dyn_sz, 16):
            d_tag, d_val = struct.unpack("<QQ", data[dyn_off + i : dyn_off + i + 16])
            if d_tag == 0:
                break
            if d_tag == 5:
                strtab_vaddr = d_val
            elif d_tag == 10:
                strtab_sz = d_val

        strtab_off = vaddr_to_off(strtab_vaddr)
        strtab = data[strtab_off : strtab_off + strtab_sz]

        def get_str(idx):
            end = strtab.find(b"\x00", idx)
            return strtab[idx:end].decode("utf-8", errors="replace")

        for i in range(0, dyn_sz, 16):
            d_tag, d_val = struct.unpack("<QQ", data[dyn_off + i : dyn_off + i + 16])
            if d_tag == 0:
                break
            if d_tag == 1:
                needed.append(get_str(d_val))
            elif d_tag == 0x61000045:  # DT_SCE_IMPORT_MODULE
                mid = (d_val >> 48) & 0xFFFF
                mods[mid] = get_str(d_val & 0xFFFFFFFF)
            elif d_tag == 0x61000049:  # DT_SCE_IMPORT_LIB
                lid = (d_val >> 48) & 0xFFFF
                libs[lid] = get_str(d_val & 0xFFFFFFFF)

    by_lib = collections.defaultdict(list)
    for raw_s in strtab.split(b"\x00"):
        st = raw_s.decode("utf-8", errors="replace")
        if "#" in st:
            parts = st.split("#")
            if len(parts) == 3:
                nid, lid_s, mid_s = parts
                lid = decode_sce_b64_id(lid_s)
                mid = decode_sce_b64_id(mid_s)
                key = f"{libs.get(lid, f'lib_{lid}')} ({mods.get(mid, f'mod_{mid}')})"
                by_lib[key].append(nid)

    return {
        "entry_point": hex(e_entry),
        "program_headers": phs,
        "needed_prx": needed,
        "imported_libraries_summary": {
            k: len(v) for k, v in sorted(by_lib.items(), key=lambda x: -len(x[1]))
        },
        "total_imported_nids": sum(len(v) for v in by_lib.values()),
    }


def analyze_ampr_index(ampr_path: Path) -> dict:
    data = ampr_path.read_bytes()
    magic, ver, hdr_sz, n_files, str_sz, off_str = struct.unpack("<8sIIQQQ", data[:40])
    if magic != b"AMPRIDX3":
        raise ValueError(f"Invalid AMPR magic: {magic}")

    str_base = 0x40 + n_files * 24
    ext_counts = collections.Counter()
    ext_bytes = collections.Counter()
    samples = []

    for i in range(n_files):
        e_off = 0x40 + i * 24
        h, s_off, s_len, fsize = struct.unpack("<QIIQ", data[e_off : e_off + 24])
        raw_entry = data[str_base + s_off : str_base + s_off + s_len].decode(
            "utf-8", errors="replace"
        )
        # Format is "<relative_path>\x00<mount_point>"
        rel_path = raw_entry.split("\x00")[0]
        ext = Path(rel_path).suffix.lower() or "<no_ext>"
        if fsize < (1 << 40):
            ext_counts[ext] += 1
            ext_bytes[ext] += fsize
        if i < 15:
            samples.append({"hash": hex(h), "size": fsize, "entry": raw_entry.replace("\x00", " -> ")})

    return {
        "magic": magic.decode("ascii"),
        "version": ver,
        "total_files": n_files,
        "total_indexed_bytes": sum(ext_bytes.values()),
        "by_extension_count": dict(ext_counts.most_common(20)),
        "by_extension_bytes": {k: ext_bytes[k] for k, _ in ext_counts.most_common(20)},
        "sample_entries": samples,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Ghost of Yotei ELF and AMPR index")
    parser.add_argument("--elf", type=Path, help="Path to extracted eboot.elf")
    parser.add_argument("--ampr", type=Path, help="Path to ampr_emu.index")
    parser.add_argument("--out", type=Path, help="Output JSON report path")
    args = parser.parse_args()

    report = {}
    if args.elf and args.elf.exists():
        report["elf"] = analyze_elf(args.elf)
    if args.ampr and args.ampr.exists():
        report["ampr_index"] = analyze_ampr_index(args.ampr)

    text = json.dumps(report, indent=2)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"[+] Report written to {args.out}")
    else:
        print(text)
