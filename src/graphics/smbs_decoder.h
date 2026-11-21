#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace yotei::graphics {

struct SmbsVertex {
    float x = 0.0f, y = 0.0f, z = 0.0f;  // Unpacked 3D position (in meters)
    float u = 0.0f, v = 0.0f;            // UV texture coordinates
    float nx = 0.0f, ny = 1.0f, nz = 0.0f; // Normal vector
};

struct SmbsSubmesh {
    uint32_t index = 0;
    uint64_t hash = 0;
    uint32_t lod_flags = 0;
    uint32_t vtx_flags = 0;
    uint32_t stream_count = 0;

    // Extracted CPU geometry
    std::vector<uint16_t> indices;
    std::vector<SmbsVertex> vertices;

    // Stream byte offsets
    uint32_t ib_start = 0;
    uint32_t ib_end = 0;
    uint32_t pos_start = 0;
    uint32_t pos_end = 0;
    uint32_t uv_start = 0;
    uint32_t uv_end = 0;
    uint32_t norm_start = 0;
    uint32_t norm_end = 0;
    uint32_t bvh_start = 0;
};

struct SmbsModel {
    std::string asset_name;
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    uint32_t num_submeshes = 0;
    uint32_t num_lods = 0;
    uint32_t total_vertices = 0;
    uint32_t total_indices = 0;
    uint32_t total_triangles = 0;

    std::vector<SmbsSubmesh> submeshes;

    // Packed contiguous buffers ready for direct 64-bit BDA GPU upload
    std::vector<SmbsVertex> packed_vertices;
    std::vector<uint16_t>   packed_indices;
};

class SmbsDecoder {
public:
    static SmbsDecoder& Instance();

    bool DecodeFromFile(const std::string& filepath, SmbsModel& out_model);
    bool DecodeFromMemory(const uint8_t* data, size_t size, const std::string& name, SmbsModel& out_model);

private:
    SmbsDecoder() = default;
};

} // namespace yotei::graphics
