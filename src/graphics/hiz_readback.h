#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace yotei::graphics {

struct HizBoundingBox {
    float min_x = 0.0f, min_y = 0.0f, min_z = 0.0f;
    float max_x = 0.0f, max_y = 0.0f, max_z = 0.0f;
};

struct HizMipLevel {
    uint32_t width = 0;
    uint32_t height = 0;
    size_t   pixel_count = 0;
    size_t   byte_offset = 0;
    std::vector<float> data;
};

struct HizStatistics {
    uint64_t total_queries = 0;
    uint64_t occluded_count = 0;
    uint64_t visible_count = 0;
    uint64_t sync_transfers = 0;
};

class HizReadbackEngine {
public:
    static HizReadbackEngine& Instance();

    // Initialize Hi-Z with native Sucker Punch resolution (default 960x540)
    bool Initialize(uint32_t width = 960, uint32_t height = 540, uint32_t max_mips = 6);
    void Shutdown();

    // Populate CPU linear buffer with initial synthetic test depth scene
    void PopulateDepthPattern(float base_depth = 0.5f);

    // Build the hierarchical depth pyramid (downsampling mips with conservative depth)
    void BuildHierarchicalPyramid(bool reverse_z = true);

    // Query occlusion for a 3D bounding box (returns true if object is occluded/culled)
    bool QueryOcclusion(const HizBoundingBox& bbox, bool reverse_z = true);

    // Sample depth value at UV coordinates on a specific mip level
    float SampleDepth(float u, float v, uint32_t mip = 0) const;

    // Direct access to linear CPU buffer
    float* GetHostBuffer() { return host_linear_buffer_.data(); }
    const float* GetHostBuffer() const { return host_linear_buffer_.data(); }
    size_t GetBufferSize() const { return host_linear_buffer_.size() * sizeof(float); }

    // Dimensions and properties
    uint32_t GetWidth() const { return base_width_; }
    uint32_t GetHeight() const { return base_height_; }
    uint32_t GetMipCount() const { return static_cast<uint32_t>(pyramid_levels_.size()); }
    bool IsInitialized() const { return initialized_; }
    const HizStatistics& GetStats() const { return stats_; }

private:
    HizReadbackEngine() = default;

    bool initialized_ = false;
    uint32_t base_width_ = 960;
    uint32_t base_height_ = 540;
    std::vector<float> host_linear_buffer_;
    std::vector<HizMipLevel> pyramid_levels_;
    HizStatistics stats_{};
};

} // namespace yotei::graphics
