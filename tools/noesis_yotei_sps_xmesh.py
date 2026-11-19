"""
noesis_yotei_sps_xmesh.py - Noesis Plugin for Sucker Punch Ghost of Yotei (PS5)
Place this file in your Noesis `plugins/python/` folder to preview and convert:
  - .sps   (XTBS v1.30 textures)
  - .xmesh (SMBS v1.0.2 3D meshes with all submeshes & LODs)
"""
from inc_noesis import *
import struct

SENTINEL = b"\x13\xad\xdb\xba"


def registerNoesisTypes():
    handle = noesis.register("Ghost of Yotei PS5 Texture", ".sps")
    noesis.setHandlerTypeCheck(handle, spsCheckType)
    noesis.setHandlerLoadRGBA(handle, spsLoadRGBA)

    mhandle = noesis.register("Ghost of Yotei PS5 Mesh", ".xmesh")
    noesis.setHandlerTypeCheck(mhandle, xmeshCheckType)
    noesis.setHandlerLoadModel(mhandle, xmeshLoadModel)
    return 1


def spsCheckType(data):
    return 1 if len(data) > 0x58 and data[:4] == b"XTBS" else 0


def spsLoadRGBA(data, texList):
    idx1 = data.find(SENTINEL)
    idx2 = data.find(SENTINEL, idx1 + 4)
    if idx1 == -1 or idx2 == -1:
        return 0
    unk, asset_hash, agc_fmt, tile_mode, swizzle, width, height, depth, mips = (
        struct.unpack("<IQHBBHHHH", data[idx1 + 4 : idx2])
    )
    payload = data[idx2 + 4 :]

    # Decode common formats (BC1, BC4, BC7, RGBA8)
    if agc_fmt == 0x0600:
        rgba = rapi.imageDecodeDXT(payload, width, height, noesis.FOURCC_BC1)
    elif agc_fmt in (0x0800, 0x0900):
        rgba = rapi.imageDecodeDXT(payload, width, height, noesis.FOURCC_BC4)
    elif agc_fmt == 0x0E00:
        rgba = rapi.imageDecodeDXT(payload, width, height, noesis.FOURCC_BC7)
    else:
        rgba = rapi.imageDecodeRaw(payload, width, height, "r8g8b8a8")

    texList.append(NoeTexture("yotei_tex", width, height, rgba, noesis.NOESISTEX_RGBA32))
    return 1


def xmeshCheckType(data):
    return 1 if len(data) > 0x3A and data[:4] == b"SMBS" else 0


def xmeshLoadModel(data, mdlList):
    ctx = rapi.rpgCreateContext()
    idx1 = data.find(SENTINEL)
    idx2 = data.find(SENTINEL, idx1 + 4)
    if idx1 == -1 or idx2 == -1:
        return 0

    num_submeshes = struct.unpack("<I", data[idx1 + 4 : idx1 + 8])[0]
    num_lods = struct.unpack("<I", data[idx2 + 4 : idx2 + 8])[0]
    stream_base = idx2 + 12 + num_lods * 5
    stream_data = data[stream_base:]

    pos = idx1 + 8
    for i in range(num_submeshes):
        sm_hash, ib_off, flg_lod, flg_vtx, n_streams = struct.unpack("<QIBBB", data[pos : pos + 15])
        pos += 15
        n_offs = n_streams + 2
        offs = list(struct.unpack(f"<{n_offs}I", data[pos : pos + n_offs * 4]))
        pos += n_offs * 4
        while len(offs) < 8:
            offs.append(0xFFFFFFFF)

        ib_bytes = stream_data[ib_off : offs[0]]
        vtx_bytes = stream_data[offs[1] : offs[2]]
        if not ib_bytes or not vtx_bytes or len(vtx_bytes) < 8:
            continue

        n_indices = len(ib_bytes) // 2
        n_verts = len(vtx_bytes) // 8
        rapi.rpgSetName(f"submesh_{i}_{hex(sm_hash)}")
        rapi.rpgBindPositionBufferOfs(vtx_bytes[: n_verts * 8], noesis.RPGEODATA_SHORT, 8, 0)
        rapi.rpgCommitTriangles(ib_bytes[: n_indices * 2], noesis.RPGEODATA_USHORT, n_indices, noesis.RPGEO_TRIANGLE, 1)
        rapi.rpgClearBufferBinds()

    mdl = rapi.rpgConstructModel()
    mdlList.append(mdl)
    return 1
