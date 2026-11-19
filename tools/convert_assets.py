#!/usr/bin/env python3
"""
convert_assets.py - Ghost of Yotei (PPSA26344) Asset Converter & Extractor
Supports:
  1. SMBS (.xmesh) -> Wavefront OBJ (.obj) + Oodle Kraken decompression of embedded PSR_BVHC ray-tracing BVH chunks
  2. XTBS (.sps)   -> DirectDraw Surface (.dds) for Noesis / RenderDoc / Blender
  3. KCAP (.xpps)  -> Stream & Shader block extraction (Magic '1234' / OrbShdr RDNA2 binaries)
"""
import argparse
import ctypes
import json
import struct
from pathlib import Path

SENTINEL = bytes.fromhex("13addbba")


def load_oodle(dll_path: Path):
    if not dll_path.exists():
        return None
    dll = ctypes.CDLL(str(dll_path))
    fn = dll.OodleLZ_Decompress
    fn.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    fn.restype = ctypes.c_int64
    return fn


def oodle_decompress(fn, comp_bytes: bytes, raw_len: int) -> bytes:
    comp_buf = ctypes.create_string_buffer(comp_bytes)
    out_buf = ctypes.create_string_buffer(raw_len)
    res = fn(
        ctypes.byref(comp_buf),
        len(comp_bytes),
        ctypes.byref(out_buf),
        raw_len,
        1,
        0,
        0,
        None,
        0,
        None,
        None,
        None,
        0,
        3,
    )
    if res <= 0:
        raise RuntimeError(f"OodleLZ_Decompress failed (returned {res})")
    return out_buf.raw[:res]


def convert_xmesh_to_obj(xmesh_path: Path, out_dir: Path, oodle_fn=None) -> dict:
    data = xmesh_path.read_bytes()
    if data[:4] != b"SMBS":
        raise ValueError(f"Not an SMBS (.xmesh) file: {xmesh_path}")

    idx1 = data.find(SENTINEL)
    idx2 = data.find(SENTINEL, idx1 + 4)
    if idx1 == -1 or idx2 == -1:
        raise ValueError(f"Missing 0xbadbad13 sentinels in {xmesh_path}")

    num_submeshes = struct.unpack("<I", data[idx1 + 4 : idx1 + 8])[0]
    submeshes = []
    pos = idx1 + 8
    for i in range(num_submeshes):
        sm_hash, ib_off, flg_lod, flg_vtx, n_streams = struct.unpack(
            "<QIBBB", data[pos : pos + 15]
        )
        pos += 15
        # Number of u32 offset entries depends on stream_count (6 -> 8 offsets, 5 -> 7 offsets, 4 -> 6 offsets)
        n_offs = n_streams + 2
        offs = list(struct.unpack(f"<{n_offs}I", data[pos : pos + n_offs * 4]))
        pos += n_offs * 4
        while len(offs) < 8:
            offs.append(0xFFFFFFFF)
        submeshes.append(
            {
                "index": i,
                "hash": hex(sm_hash),
                "ib_start": ib_off,
                "ib_end": offs[0],
                "pos_start": offs[1],
                "pos_end": offs[2],
                "uv_start": offs[3],
                "uv_end": offs[4],
                "norm_start": offs[5],
                "norm_end": offs[6],
                "bvh_start": offs[7],
                "lod_flags": hex(flg_lod),
                "vtx_flags": hex(flg_vtx),
                "stream_count": n_streams,
            }
        )

    num_lods = struct.unpack("<I", data[idx2 + 4 : idx2 + 8])[0]
    # Header after idx2: u32 num_lods, u32 unk_flags, then num_lods * 5-byte entries
    stream_base = idx2 + 12 + num_lods * 5
    stream_data = data[stream_base:]

    out_dir.mkdir(parents=True, exist_ok=True)
    obj_lines = [
        f"# Extracted from Ghost of Yotei: {xmesh_path.name}",
        f"# Submeshes: {num_submeshes}, LOD groups: {num_lods}",
    ]

    global_v_offset = 1
    exported_submeshes = 0
    bvh_extracted = 0

    for sm in submeshes:
        ib_bytes = stream_data[sm["ib_start"] : sm["ib_end"]]
        pos_bytes = stream_data[sm["pos_start"] : sm["pos_end"]]
        if not ib_bytes or not pos_bytes or len(pos_bytes) < 8:
            continue

        n_indices = len(ib_bytes) // 2
        n_verts = len(pos_bytes) // 8
        indices = struct.unpack(f"<{n_indices}H", ib_bytes[: n_indices * 2])

        obj_lines.append(f"\ng submesh_{sm['index']}_{sm['hash']}")
        for v in range(n_verts):
            qx, qy, qz, qw = struct.unpack("<hhhh", pos_bytes[v * 8 : (v + 1) * 8])
            # Normalize int16 coordinates to meter scale
            fx, fy, fz = qx / 32767.0, qy / 32767.0, qz / 32767.0
            obj_lines.append(f"v {fx:.6f} {fy:.6f} {fz:.6f}")

        # Optional UV stream (8 bytes per vertex: half-float or snorm16 pairs)
        uv_bytes = (
            stream_data[sm["uv_start"] : sm["uv_end"]]
            if sm["uv_start"] != 0xFFFFFFFF and sm["uv_end"] != 0xFFFFFFFF
            else b""
        )
        has_uv = len(uv_bytes) >= n_verts * 8
        if has_uv:
            for v in range(n_verts):
                u_h, v_h = struct.unpack("<ee", uv_bytes[v * 8 + 4 : v * 8 + 8])
                if not (abs(u_h) < 100.0 and abs(v_h) < 100.0):
                    u_h, v_h = 0.0, 0.0
                obj_lines.append(f"vt {u_h:.6f} {v_h:.6f}")

        for t in range(0, n_indices - 2, 3):
            i0 = indices[t] + global_v_offset
            i1 = indices[t + 1] + global_v_offset
            i2 = indices[t + 2] + global_v_offset
            if has_uv:
                obj_lines.append(f"f {i0}/{i0} {i1}/{i1} {i2}/{i2}")
            else:
                obj_lines.append(f"f {i0} {i1} {i2}")

        global_v_offset += n_verts
        exported_submeshes += 1

        # Check for Oodle Kraken compressed PSR_BVHC ray-tracing BVH chunk in norm_end..bvh_start
        if (
            oodle_fn
            and sm["norm_end"] != 0xFFFFFFFF
            and sm["bvh_start"] != 0xFFFFFFFF
            and sm["bvh_start"] > sm["norm_end"]
        ):
            bvh_chunk = stream_data[sm["norm_end"] : sm["bvh_start"]]
            if len(bvh_chunk) > 8 and bvh_chunk[0] == 0x8C:
                try:
                    # 24-bit big-endian quantum length at bytes 2..5 (+ 1)
                    q_len = ((bvh_chunk[2] << 16) | (bvh_chunk[3] << 8) | bvh_chunk[4]) + 1
                    raw_bvh = oodle_decompress(oodle_fn, bvh_chunk, q_len)
                    bvh_out = out_dir / f"{xmesh_path.stem}_submesh{sm['index']}.bvhc"
                    bvh_out.write_bytes(raw_bvh)
                    bvh_extracted += 1
                except Exception:
                    pass

    # Also scan stream_data for all embedded Oodle Kraken PSR_BVHC ray-tracing BVH chunks
    if oodle_fn:
        bvh_pos = 0
        while True:
            idx_bvh = stream_data.find(b"PSR_BVHC", bvh_pos)
            if idx_bvh == -1 or idx_bvh < 8:
                break
            hdr_start = idx_bvh - 8
            if stream_data[hdr_start] == 0x8C:
                q_comp_len = (
                    (stream_data[hdr_start + 2] << 16)
                    | (stream_data[hdr_start + 3] << 8)
                    | stream_data[hdr_start + 4]
                )
                raw_len = q_comp_len + 1
                comp_slice = stream_data[hdr_start : hdr_start + 6 + q_comp_len]
                try:
                    raw_bvh = oodle_decompress(oodle_fn, comp_slice, raw_len)
                    bvh_out = out_dir / f"{xmesh_path.stem}_bvh{bvh_extracted}.bvhc"
                    bvh_out.write_bytes(raw_bvh)
                    bvh_extracted += 1
                except Exception as e:
                    print(f"[!] BVH decompress error at {hex(hdr_start)}: {e}")
            bvh_pos = idx_bvh + 8

    obj_path = out_dir / f"{xmesh_path.stem}.obj"
    obj_path.write_text("\n".join(obj_lines), encoding="utf-8")
    return {
        "input": str(xmesh_path),
        "output_obj": str(obj_path),
        "num_submeshes": num_submeshes,
        "exported_submeshes": exported_submeshes,
        "total_vertices": global_v_offset - 1,
        "bvh_chunks_decompressed": bvh_extracted,
    }


def make_dds_header(width: int, height: int, depth: int, mips: int, agc_fmt: int) -> bytes:
    # Map common AGC format codes to FourCC / DXGI format via standard DDS header
    DDSD_CAPS = 0x1
    DDSD_HEIGHT = 0x2
    DDSD_WIDTH = 0x4
    DDSD_PIXELFORMAT = 0x1000
    DDSD_MIPMAPCOUNT = 0x20000
    DDSD_LINEARSIZE = 0x80000

    flags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT | DDSD_LINEARSIZE
    if mips > 1:
        flags |= DDSD_MIPMAPCOUNT

    # Default pixel format: DX10 header extension for BC1/BC4/BC7/R8G8B8A8
    ddspf = struct.pack(
        "<II4sIIIII",
        32,
        0x4,  # DDPF_FOURCC
        b"DX10",
        0,
        0,
        0,
        0,
        0,
    )

    # Map observed Ghost of Yotei AGC format codes to DXGI_FORMAT:
    # 0x0800 (1 Bpp, e.g. debugfont 512x512 = 262144 bytes) -> DXGI_FORMAT_R8_UNORM (61) or BC4_UNORM (80)
    # 0x0600 / 0x0900 (0.5 Bpp with mips, 1024x1024x11 = 700416) -> DXGI_FORMAT_BC1_UNORM (71) / BC4_UNORM (80)
    # 0x0e00 (1 Bpp with mips, 1024x1024x11 = 1400832) -> DXGI_FORMAT_BC7_UNORM (98)
    # 0x0002 / 0x1002 (4 Bpp 3D LUT 32x32x32 = 131072) -> DXGI_FORMAT_R8G8B8A8_UNORM (28)
    dxgi_map = {
        0x0800: 61,  # DXGI_FORMAT_R8_UNORM
        0x0600: 71,  # DXGI_FORMAT_BC1_UNORM
        0x0900: 80,  # DXGI_FORMAT_BC4_UNORM
        0x0E00: 98,  # DXGI_FORMAT_BC7_UNORM
        0x0002: 28,  # DXGI_FORMAT_R8G8B8A8_UNORM
        0x1002: 28,  # DXGI_FORMAT_R8G8B8A8_UNORM
        0x0000: 28,  # DXGI_FORMAT_R8G8B8A8_UNORM
    }
    dxgi_fmt = dxgi_map.get(agc_fmt, 28)
    res_dim = 4 if depth > 1 else 3  # D3D10_RESOURCE_DIMENSION_TEXTURE3D (4) vs TEXTURE2D (3)

    hdr = struct.pack(
        "<4sIIIIIII44x",
        b"DDS ",
        124,
        flags,
        height,
        width,
        width * height,
        depth if depth > 1 else 1,
        mips if mips > 1 else 1,
    )
    caps = struct.pack("<IIIII", 0x1000, 0x200000 if depth > 1 else 0, 0, 0, 0)
    dx10 = struct.pack("<IIIII", dxgi_fmt, res_dim, 0, 1, 0)
    return hdr + ddspf + caps + dx10


def convert_sps_to_dds(sps_path: Path, out_dir: Path) -> dict:
    data = sps_path.read_bytes()
    if data[:4] != b"XTBS":
        raise ValueError(f"Not an XTBS (.sps) file: {sps_path}")

    idx1 = data.find(SENTINEL)
    idx2 = data.find(SENTINEL, idx1 + 4)
    if idx1 == -1 or idx2 == -1:
        raise ValueError(f"Missing 0xbadbad13 sentinels in {sps_path}")

    desc = data[idx1 + 4 : idx2]
    unk, asset_hash, agc_fmt, tile_mode, swizzle, width, height, depth, mips = (
        struct.unpack("<IQHBBHHHH", desc)
    )
    payload = data[idx2 + 4 :]

    out_dir.mkdir(parents=True, exist_ok=True)
    dds_path = out_dir / f"{sps_path.stem}.dds"
    dds_hdr = make_dds_header(width, height, depth, mips, agc_fmt)
    dds_path.write_bytes(dds_hdr + payload)

    return {
        "input": str(sps_path),
        "output_dds": str(dds_path),
        "asset_hash": hex(asset_hash),
        "dimensions": f"{width}x{height}x{depth}",
        "mip_levels": mips,
        "agc_format": hex(agc_fmt),
        "tile_mode": tile_mode,
        "payload_bytes": len(payload),
    }


def extract_xpps_shaders(xpps_path: Path, out_dir: Path, max_shaders: int = 25) -> dict:
    data = xpps_path.read_bytes()
    if data[:4] != b"KCAP":
        raise ValueError(f"Not a KCAP (.xpps) file: {xpps_path}")

    hdr_sz, sec_sz, data_off, file_sz = struct.unpack("<IIII", data[0x40:0x50])
    n_streams = struct.unpack("<I", data[0x58:0x5C])[0]

    out_dir.mkdir(parents=True, exist_ok=True)
    pos = data_off
    extracted = []
    while len(extracted) < max_shaders:
        idx = data.find(b"1234", pos)
        if idx == -1 or idx < 0x28:
            break
        rec_start = idx - 0x28
        code_rel, code_sz = struct.unpack("<QQ", data[rec_start + 8 : rec_start + 24])
        orb_idx = data.find(b"OrbShdr", idx)
        extracted.append(
            {
                "index": len(extracted),
                "record_offset": hex(rec_start),
                "code_rel_offset": hex(code_rel),
                "code_size": code_sz,
                "has_orbshdr_footer": (orb_idx != -1 and orb_idx - idx < 0x10000),
            }
        )
        pos = idx + 4

    meta_path = out_dir / f"{xpps_path.stem}_shaders.json"
    meta_path.write_text(json.dumps(extracted, indent=2), encoding="utf-8")
    return {
        "input": str(xpps_path),
        "kcap_streams": n_streams,
        "data_offset": hex(data_off),
        "total_1234_headers_in_pack": data.count(b"1234"),
        "sample_manifest": str(meta_path),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost of Yotei Asset Converter (.xmesh, .sps, .xpps)")
    parser.add_argument("--xmesh", type=Path, help="Input .xmesh file to convert to .obj")
    parser.add_argument("--sps", type=Path, help="Input .sps file to convert to .dds")
    parser.add_argument("--xpps", type=Path, help="Input .xpps file to inspect/extract shaders")
    parser.add_argument(
        "--oodle-dll",
        type=Path,
        default=Path(r"c:\Users\Alvaro\Downloads\Projects\YoteiPort\PS5PKGTool-v1.3.0\oo2core_9_win64.dll"),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(r"c:\Users\Alvaro\Downloads\Projects\YoteiPort\extracted_assets"),
    )
    args = parser.parse_args()

    oodle_fn = load_oodle(args.oodle_dll)
    results = {}
    if args.xmesh:
        results["xmesh"] = convert_xmesh_to_obj(args.xmesh, args.out_dir, oodle_fn)
    if args.sps:
        results["sps"] = convert_sps_to_dds(args.sps, args.out_dir)
    if args.xpps:
        results["xpps"] = extract_xpps_shaders(args.xpps, args.out_dir)
    print(json.dumps(results, indent=2))
