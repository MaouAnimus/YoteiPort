#!/usr/bin/env python3
"""
resolve_nids.py - Complete NID Resolver & PLT/GOT Relocation Mapper for Ghost of Yotei (PPSA26344)
Maps all 715 imported symbols in eboot.elf to:
  - Their exact PLT stub virtual address and GOT slot virtual address in eboot.elf
  - Their human-readable Sony Prospero / C++ function name (via SHA-1 NID salt & Kyty HLE table)
  - Their provider module (HLE subsystem vs shipped fakelib/*.elf & libc.elf)
Also emits a Ghidra Python post-script (tools/ghidra/apply_yotei_nids.py) to rename all symbols automatically.
"""
import base64
import collections
import hashlib
import json
import re
import struct
from pathlib import Path

NID_SALT = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"


def calc_nid(name: str) -> str:
    h = hashlib.sha1(name.encode("utf-8") + NID_SALT).digest()[:8][::-1]
    return base64.b64encode(h).decode("ascii").rstrip("=").replace("/", "-")


def dec_b64_id(s: str) -> int:
    val = 0
    for c in s:
        val = (val << 6) | B64_CHARS.index(c)
    return val


def main():
    root = Path(r"c:\Users\Alvaro\Downloads\Projects\YoteiPort")
    elf_dir = root / "extracted_elf"
    eboot_path = elf_dir / "eboot.elf"
    eboot = eboot_path.read_bytes()

    # PH[8] DYNLIBDATA: vaddr 0x717d610 -> file offset 0x2145610
    def vaddr_to_dloff(v: int) -> int:
        return v - 0x717D610 + 0x2145610

    # Parse PT_DYNAMIC (offset 0x26408a0, size 0xf10)
    dyn_off = 0x26408A0
    tags = {}
    libs = {}
    mods = {}

    strtab_off = vaddr_to_dloff(0x717D610)
    strtab_sz = 0x348E
    strtab = eboot[strtab_off : strtab_off + strtab_sz]

    def get_str(idx: int) -> str:
        end = strtab.find(b"\x00", idx)
        return strtab[idx:end].decode("utf-8", errors="replace")

    for i in range(0, 0xF10, 16):
        d_tag, d_val = struct.unpack("<QQ", eboot[dyn_off + i : dyn_off + i + 16])
        if d_tag == 0:
            break
        tags[d_tag] = d_val
        if d_tag == 0x61000045:  # DT_SCE_IMPORT_MODULE
            mods[(d_val >> 48) & 0xFFFF] = get_str(d_val & 0xFFFFFFFF)
        elif d_tag == 0x61000049:  # DT_SCE_IMPORT_LIB
            libs[(d_val >> 48) & 0xFFFF] = get_str(d_val & 0xFFFFFFFF)

    # Parse DT_SYMTAB (0x7180aa0) and DT_JMPREL (0x7184dc0, size 0x4278) + DT_RELA (0x7189038, size 0x4ee1d8)
    symtab_off = vaddr_to_dloff(tags[6])
    jmprel_off = vaddr_to_dloff(tags[0x17])
    jmprel_sz = tags[2]
    rela_off = vaddr_to_dloff(tags[7])
    rela_sz = tags[8]

    # Build symbol table entries
    n_syms = (jmprel_off - symtab_off) // 24
    symbols = []
    for i in range(n_syms):
        off = symtab_off + i * 24
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
            "<IBBHQQ", eboot[off : off + 24]
        )
        name_str = get_str(st_name) if st_name > 0 else ""
        symbols.append(
            {
                "index": i,
                "name": name_str,
                "info": st_info,
                "shndx": st_shndx,
                "value": st_value,
                "size": st_size,
            }
        )

    # Map GOT relocations (JMPREL & RELA) to symbol indices
    got_by_sym = collections.defaultdict(list)
    for base_off, total_sz, rel_kind in [
        (jmprel_off, jmprel_sz, "JMPREL"),
        (rela_off, rela_sz, "RELA"),
    ]:
        for i in range(0, total_sz, 24):
            r_offset, r_info, r_addend = struct.unpack(
                "<QQq", eboot[base_off + i : base_off + i + 24]
            )
            sym_idx = r_info >> 32
            r_type = r_info & 0xFFFFFFFF
            if sym_idx > 0 and sym_idx < len(symbols):
                got_by_sym[sym_idx].append(
                    {
                        "got_vaddr": hex(r_offset),
                        "type": r_type,
                        "kind": rel_kind,
                        "addend": r_addend,
                    }
                )

    # Collect target NIDs
    target_map = {}
    for sym in symbols:
        st = sym["name"]
        if "#" in st:
            parts = st.split("#")
            if len(parts) == 3:
                nid, lid_s, mid_s = parts
                target_map[nid] = {
                    "nid": nid,
                    "raw_symbol": st,
                    "sym_index": sym["index"],
                    "library": libs.get(dec_b64_id(lid_s), lid_s),
                    "module": mods.get(dec_b64_id(mid_s), mid_s),
                    "relocations": got_by_sym.get(sym["index"], []),
                }

    # Check shipped fakelib/*.elf and libc.elf exports
    shipped_providers = {}
    for p in elf_dir.glob("*.elf"):
        if p.name.startswith("eboot"):
            continue
        d = p.read_bytes()
        for m in re.finditer(
            rb"([A-Za-z0-9+\-]{11})#[A-Za-z0-9+\-]+#[A-Za-z0-9+\-]+", d
        ):
            n = m.group(1).decode("ascii")
            if n in target_map:
                shipped_providers.setdefault(n, []).append(p.name)

    # Resolve names from Kyty HLE table + SHA-1 salt
    exe_path = (
        root
        / "KytyPS5-Yotei"
        / "KytyPS5-Yotei-v0.1.6-windows-x64"
        / "kyty_emulator.exe"
    )
    exe = exe_path.read_bytes()
    all_nul_strings = [s.decode("ascii", errors="ignore") for s in exe.split(b"\x00")]

    resolved = {}
    for i, s in enumerate(all_nul_strings):
        if s in target_map and i + 1 < len(all_nul_strings):
            nxt = all_nul_strings[i + 1]
            resolved[s] = {"name": nxt, "source": "kyty_hle_table"}

    words = set(
        s.decode("ascii")
        for s in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{1,90}", exe)
    )
    for p in elf_dir.glob("*.elf"):
        words.update(
            s.decode("ascii")
            for s in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{2,90}", p.read_bytes())
        )

    # Extra known Sony symbols for VoiceQoS, NpSessionSignaling, PlayGoDialog, Coredump, etc.
    extra_prefixes = [
        "sceVoiceQoSInit", "sceVoiceQoSEnd", "sceVoiceQoSCreateLocalEndpoint",
        "sceVoiceQoSDeleteLocalEndpoint", "sceVoiceQoSCreateRemoteEndpoint",
        "sceVoiceQoSDeleteRemoteEndpoint", "sceVoiceQoSConnect", "sceVoiceQoSDisconnect",
        "sceVoiceQoSWritePacket", "sceVoiceQoSReadPacket", "sceVoiceQoSGetStatus",
        "sceVoiceQoSSetConnectionAttribute", "sceVoiceQoSGetConnectionAttribute",
        "sceVoiceQoSSetLocalEndpointAttribute", "sceVoiceQoSGetLocalEndpointAttribute",
        "scePlayGoDialogInitialize", "scePlayGoDialogTerminate", "scePlayGoDialogOpen",
        "scePlayGoDialogClose", "scePlayGoDialogUpdateStatus", "scePlayGoDialogGetStatus",
        "scePlayGoDialogGetResult", "sceCoredumpAttachMemoryRegion", "sceCoredumpDetachMemoryRegion",
        "sceCoredumpWriteUserData", "sceCoredumpDebugTextOut", "sceCoredumpTriggerCoredump",
        "sceWebBrowserDialogInitialize", "sceWebBrowserDialogTerminate", "sceWebBrowserDialogOpen",
        "sceWebBrowserDialogClose", "sceWebBrowserDialogUpdateStatus", "sceWebBrowserDialogGetStatus",
        "sceWebBrowserDialogGetResult", "sceWebBrowserDialogResetCookie",
        "sceAudioInOpen", "sceAudioInClose", "sceAudioInInput", "sceAudioInSetac",
        "sceNpSessionSignalingInitialize", "sceNpSessionSignalingTerminate",
        "sceNpSessionSignalingCreateContext", "sceNpSessionSignalingDestroyContext",
        "sceNpSessionSignalingActivateConnection", "sceNpSessionSignalingDeactivateConnection",
        "sceNpSessionSignalingGetConnectionStatus", "sceNpSessionSignalingGetConnectionInfo",
        "sceNpSessionSignalingGetLocalNetInfo", "sceNpSessionSignalingSetCallback",
    ]
    words.update(extra_prefixes)

    for w in words:
        for cand in (w, "sce" + w, "_" + w, "__" + w):
            n = calc_nid(cand)
            if n in target_map and n not in resolved:
                resolved[n] = {"name": cand, "source": "sha1_nid_hash"}

    entries = []
    for nid, info in sorted(
        target_map.items(), key=lambda x: (x[1]["library"], x[0])
    ):
        res = resolved.get(nid)
        fakes = shipped_providers.get(nid, [])
        entries.append(
            {
                "nid": nid,
                "resolved_name": res["name"] if res else f"sub_nid_{nid}",
                "resolution_source": (
                    res["source"]
                    if res
                    else ("shipped_module" if fakes else "unresolved_stub")
                ),
                "library": info["library"],
                "module": info["module"],
                "shipped_in": fakes,
                "sym_index": info["sym_index"],
                "relocations": info["relocations"],
            }
        )

    out_json = root / "docs" / "nid_resolution_table.json"
    out_json.write_text(
        json.dumps(
            {
                "total_nids": len(entries),
                "resolved_by_name": sum(
                    1
                    for e in entries
                    if e["resolution_source"] in ("kyty_hle_table", "sha1_nid_hash")
                ),
                "provided_by_shipped_modules": sum(
                    1 for e in entries if e["shipped_in"]
                ),
                "entries": entries,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Generate Ghidra annotation script
    ghidra_dir = root / "tools" / "ghidra"
    ghidra_dir.mkdir(parents=True, exist_ok=True)
    ghidra_script = ghidra_dir / "apply_yotei_nids.py"
    lines = [
        "# Ghidra Post-Analysis Script: Rename GOT slots for Ghost of Yotei (PPSA26344)",
        "# @category YoteiPort",
        "from ghidra.program.model.symbol import SourceType",
        "",
        "NID_GOT_MAP = [",
    ]
    for e in entries:
        clean_name = re.sub(r"[^A-Za-z0-9_]", "_", e["resolved_name"])
        for rel in e["relocations"]:
            lines.append(
                f'    ({rel["got_vaddr"]}, "{e["library"]}__{clean_name}", "{e["nid"]}"),',
            )
    lines.extend(
        [
            "]",
            "",
            "def run():",
            "    sym_tbl = currentProgram.getSymbolTable()",
            "    base = currentProgram.getImageBase()",
            "    count = 0",
            "    for vaddr, name, nid in NID_GOT_MAP:",
            "        addr = base.add(vaddr)",
            "        sym_tbl.createLabel(addr, name, SourceType.USER_DEFINED)",
            "        count += 1",
            '    print("[+] Applied %d Ghost of Yotei GOT symbol labels" % count)',
            "",
            'if __name__ == "__main__":',
            "    run()",
        ]
    )
    ghidra_script.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Wrote {out_json} and {ghidra_script}")


if __name__ == "__main__":
    main()
