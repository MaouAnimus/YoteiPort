#include "smbs_decoder.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <cmath>
#include <immintrin.h>

namespace yotei::graphics {

static constexpr uint32_t SMBS_SENTINEL = 0xbadbad13;

static inline float Fp16ToFp32(uint16_t h) {
#if defined(__AVX2__) || defined(_MSC_VER)
    __m128i ph = _mm_cvtsi32_si128(static_cast<int>(h));
    __m128 ps = _mm_cvtph_ps(ph);
    return _mm_cvtss_f32(ps);
#else
    uint32_t sign = (h >> 15) & 0x0001;
    uint32_t exp  = (h >> 10) & 0x001f;
    uint32_t mant = h & 0x03ff;
    if (exp == 0) {
        if (mant == 0) return (sign != 0) ? -0.0f : 0.0f;
        while ((mant & 0x0400) == 0) { mant <<= 1; exp--; }
        exp++;
        mant &= ~0x0400;
    } else if (exp == 31) {
        uint32_t f = (sign << 31) | 0x7f800000 | (mant << 13);
        float out;
        std::memcpy(&out, &f, sizeof(float));
        return out;
    }
    exp = exp + (127 - 15);
    mant = mant << 13;
    uint32_t f = (sign << 31) | (exp << 23) | mant;
    float out;
    std::memcpy(&out, &f, sizeof(float));
    return out;
#endif
}

SmbsDecoder& SmbsDecoder::Instance() {
    static SmbsDecoder instance;
    return instance;
}

bool SmbsDecoder::DecodeFromFile(const std::string& filepath, SmbsModel& out_model) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    std::streamsize size = file.tellg();
    if (size < 0x40) return false;
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return false;

    std::string filename = filepath;
    size_t last_slash = filename.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        filename = filename.substr(last_slash + 1);
    }
    size_t dot_pos = filename.find(".xmesh");
    if (dot_pos != std::string::npos) {
        filename = filename.substr(0, dot_pos);
    }

    return DecodeFromMemory(buffer.data(), buffer.size(), filename, out_model);
}

bool SmbsDecoder::DecodeFromMemory(
    const uint8_t* data,
    size_t size,
    const std::string& name,
    SmbsModel& out_model) {
    if (!data || size < 0x40) return false;

    // Check "SMBS" magic
    if (std::memcmp(data, "SMBS", 4) != 0) {
        std::cerr << "  [SMBS ERROR] Magic mismatch: expected 'SMBS'\n";
        return false;
    }

    out_model.asset_name = name;
    out_model.version_major = *reinterpret_cast<const uint16_t*>(data + 4);
    out_model.version_minor = *reinterpret_cast<const uint16_t*>(data + 6);

    // Locate first sentinel (0xbadbad13)
    const uint8_t sentinel_bytes[4] = { 0x13, 0xad, 0xdb, 0xba };
    size_t idx1 = std::string_view(reinterpret_cast<const char*>(data), size).find(
        reinterpret_cast<const char*>(sentinel_bytes), 0, 4);

    if (idx1 == std::string_view::npos) {
        std::cerr << "  [SMBS ERROR] First sentinel 0xbadbad13 not found\n";
        return false;
    }

    // Locate second sentinel
    size_t idx2 = std::string_view(reinterpret_cast<const char*>(data), size).find(
        reinterpret_cast<const char*>(sentinel_bytes), idx1 + 4, 4);

    if (idx2 == std::string_view::npos) {
        std::cerr << "  [SMBS ERROR] Second sentinel 0xbadbad13 not found\n";
        return false;
    }

    out_model.num_submeshes = *reinterpret_cast<const uint32_t*>(data + idx1 + 4);
    out_model.num_lods = *reinterpret_cast<const uint32_t*>(data + idx2 + 4);

    // Compute stream data start
    size_t stream_base = idx2 + 12 + out_model.num_lods * 5;
    if (stream_base >= size) {
        std::cerr << "  [SMBS ERROR] Stream base out of bounds: 0x" << std::hex << stream_base << std::dec << "\n";
        return false;
    }

    const uint8_t* stream_data = data + stream_base;
    size_t stream_size = size - stream_base;

    // Parse submesh descriptors
    size_t pos = idx1 + 8;
    out_model.submeshes.clear();
    out_model.submeshes.reserve(out_model.num_submeshes);
    out_model.packed_vertices.clear();
    out_model.packed_indices.clear();

    for (uint32_t i = 0; i < out_model.num_submeshes; ++i) {
        if (pos + 15 > idx2) break;

        SmbsSubmesh sm{};
        sm.index = i;
        sm.hash = *reinterpret_cast<const uint64_t*>(data + pos);
        sm.ib_start = *reinterpret_cast<const uint32_t*>(data + pos + 8);
        sm.lod_flags = data[pos + 12];
        sm.vtx_flags = data[pos + 13];
        sm.stream_count = data[pos + 14];
        pos += 15;

        uint32_t n_offs = sm.stream_count + 2;
        if (pos + n_offs * 4 > idx2) break;

        std::vector<uint32_t> offs(8, 0xFFFFFFFFU);
        for (uint32_t o = 0; o < n_offs && o < 8; ++o) {
            offs[o] = *reinterpret_cast<const uint32_t*>(data + pos + o * 4);
        }
        pos += n_offs * 4;

        sm.ib_end     = offs[0];
        sm.pos_start  = offs[1];
        sm.pos_end    = offs[2];
        sm.uv_start   = offs[3];
        sm.uv_end     = offs[4];
        sm.norm_start = offs[5];
        sm.norm_end   = offs[6];
        sm.bvh_start  = offs[7];

        // Bounds checks
        if (sm.ib_start < stream_size && sm.ib_end <= stream_size && sm.ib_end > sm.ib_start &&
            sm.pos_start < stream_size && sm.pos_end <= stream_size && sm.pos_end > sm.pos_start) {
            
            size_t ib_bytes = sm.ib_end - sm.ib_start;
            size_t pos_bytes = sm.pos_end - sm.pos_start;
            uint32_t n_indices = static_cast<uint32_t>(ib_bytes / sizeof(uint16_t));
            uint32_t n_verts = static_cast<uint32_t>(pos_bytes / 8); // 8 bytes per quantized vertex

            if (n_indices > 0 && n_verts > 0) {
                sm.indices.resize(n_indices);
                std::memcpy(sm.indices.data(), stream_data + sm.ib_start, n_indices * sizeof(uint16_t));

                sm.vertices.resize(n_verts);
                const int16_t* raw_pos = reinterpret_cast<const int16_t*>(stream_data + sm.pos_start);

                for (uint32_t v = 0; v < n_verts; ++v) {
                    int16_t qx = raw_pos[v * 4 + 0];
                    int16_t qy = raw_pos[v * 4 + 1];
                    int16_t qz = raw_pos[v * 4 + 2];
                    sm.vertices[v].x = static_cast<float>(qx) / 32767.0f;
                    sm.vertices[v].y = static_cast<float>(qy) / 32767.0f;
                    sm.vertices[v].z = static_cast<float>(qz) / 32767.0f;
                }

                // Parse UV stream if valid
                if (sm.uv_start != 0xFFFFFFFFU && sm.uv_end != 0xFFFFFFFFU && sm.uv_end > sm.uv_start && sm.uv_end <= stream_size) {
                    size_t uv_bytes = sm.uv_end - sm.uv_start;
                    if (uv_bytes >= n_verts * 8) {
                        const uint8_t* uv_ptr = stream_data + sm.uv_start;
                        for (uint32_t v = 0; v < n_verts; ++v) {
                            const uint16_t* half_uv = reinterpret_cast<const uint16_t*>(uv_ptr + v * 8 + 4);
                            float uh = Fp16ToFp32(half_uv[0]);
                            float vh = Fp16ToFp32(half_uv[1]);
                            if (std::abs(uh) < 100.0f && std::abs(vh) < 100.0f) {
                                sm.vertices[v].u = uh;
                                sm.vertices[v].v = vh;
                            }
                        }
                    }
                }

                // Append to model packed buffers
                uint16_t base_vtx = static_cast<uint16_t>(out_model.packed_vertices.size());
                out_model.packed_vertices.insert(
                    out_model.packed_vertices.end(),
                    sm.vertices.begin(),
                    sm.vertices.end());

                for (uint16_t idx : sm.indices) {
                    out_model.packed_indices.push_back(base_vtx + idx);
                }

                out_model.total_vertices += n_verts;
                out_model.total_indices += n_indices;
            }
        }

        out_model.submeshes.push_back(std::move(sm));
    }

    out_model.total_triangles = out_model.total_indices / 3;
    return (out_model.total_vertices > 0 && out_model.total_indices > 0);
}

} // namespace yotei::graphics
