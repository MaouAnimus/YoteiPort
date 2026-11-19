#!/usr/bin/env python3
"""
unself.py - PS5 Decrypted Fake-Signed SELF / SPRX / PRX to ELF64 Converter
Part of the Ghost of Yotei (PPSA26344) Native / HLE Experimental Port Toolkit.
"""
import argparse
import struct
import sys
from pathlib import Path

SELF_MAGIC = b"\x4f\x15\x3d\x1d"
SPRX_MAGIC = b"\x54\x14\xf5\xee"
ELF_MAGIC  = b"\x7fELF"


def extract_elf(self_path: Path, elf_path: Path, patch_et_dyn: bool = False) -> dict:
    data = self_path.read_bytes()
    if data[:4] == ELF_MAGIC:
        if self_path != elf_path:
            elf_path.write_bytes(data)
        return {"status": "already_elf", "size": len(data)}

    if data[:4] not in (SELF_MAGIC, SPRX_MAGIC):
        raise ValueError(f"Unknown magic {data[:4].hex()} in {self_path}")

    num_segs = struct.unpack("<H", data[0x18:0x1A])[0]
    segs = [
        struct.unpack("<QQQQ", data[32 + i * 32 : 32 + (i + 1) * 32])
        for i in range(num_segs)
    ]

    elf_idx = data.find(ELF_MAGIC)
    if elf_idx == -1:
        raise ValueError(f"Embedded ELF64 header not found in {self_path}")

    elf_hdr = bytearray(data[elf_idx : elf_idx + 64])
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
    ) = struct.unpack("<HHIQQQIHHHHHH", elf_hdr[16:64])

    if patch_et_dyn and e_type in (0xFE10, 0xFE18):
        # Patch Sony ET_SCE_DYNEXEC (0xfe10) / ET_SCE_DYNAMIC (0xfe18) to standard ET_DYN (0x3)
        # for standard ELF tools that reject vendor-specific e_type values.
        struct.pack_into("<H", elf_hdr, 16, 3)

    phs = []
    max_end = e_phoff + e_phnum * e_phentsize
    for i in range(e_phnum):
        ph_off = elf_idx + e_phoff + i * e_phentsize
        ph = struct.unpack("<IIQQQQQQ", data[ph_off : ph_off + e_phentsize])
        phs.append(ph)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
        if p_filesz > 0 and p_offset + p_filesz > max_end:
            max_end = p_offset + p_filesz

    out = bytearray(max_end)
    out[:64] = elf_hdr
    out[e_phoff : e_phoff + e_phnum * e_phentsize] = data[
        elf_idx + e_phoff : elf_idx + e_phoff + e_phnum * e_phentsize
    ]

    mapped_segments = 0
    for s_flags, s_off, s_comp_sz, s_decomp_sz in segs:
        if s_flags & 0x800:  # Data payload segment
            ph_id = (s_flags >> 20) & 0xFFF
            p_offset = phs[ph_id][2]
            out[p_offset : p_offset + s_comp_sz] = data[s_off : s_off + s_comp_sz]
            mapped_segments += 1

    # Map trailing PT_SCE_COMMENT (0x6fffff01) if present right after the last SELF segment
    last_seg_end = max((s_off + s_comp_sz for _, s_off, s_comp_sz, _ in segs), default=0)
    for p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align in phs:
        if p_type == 0x6FFFFF01 and last_seg_end + p_filesz <= len(data):
            out[p_offset : p_offset + p_filesz] = data[
                last_seg_end : last_seg_end + p_filesz
            ]

    elf_path.parent.mkdir(parents=True, exist_ok=True)
    elf_path.write_bytes(out)
    return {
        "status": "ok",
        "original_e_type": hex(e_type),
        "entry": hex(e_entry),
        "phnum": e_phnum,
        "mapped_segments": mapped_segments,
        "output_size": len(out),
    }


def main():
    parser = argparse.ArgumentParser(description="Convert decrypted PS5 SELF/SPRX/PRX to ELF64")
    parser.add_argument("input", type=Path, help="Input SELF/SPRX/PRX file")
    parser.add_argument("output", type=Path, help="Output ELF64 file")
    parser.add_argument("--patch-et-dyn", action="store_true", help="Patch e_type 0xfe10/0xfe18 to ET_DYN (3)")
    args = parser.parse_args()

    info = extract_elf(args.input, args.output, args.patch_et_dyn)
    print(f"[+] Extracted {args.input.name} -> {args.output} ({info})")


if __name__ == "__main__":
    main()
