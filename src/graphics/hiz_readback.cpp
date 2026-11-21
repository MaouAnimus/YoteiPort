#include "hiz_readback.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>

namespace yotei::graphics {

HizReadbackEngine& HizReadbackEngine::Instance() {
    static HizReadbackEngine instance;
    return instance;
}

bool HizReadbackEngine::Initialize(uint32_t width, uint32_t height, uint32_t max_mips) {
    base_width_ = width;
    base_height_ = height;
    host_linear_buffer_.resize(width * height, 0.0f);

    pyramid_levels_.clear();
    uint32_t cur_w = width;
    uint32_t cur_h = height;
    size_t offset = 0;

    for (uint32_t m = 0; m < max_mips; ++m) {
        HizMipLevel lvl{};
        lvl.width = cur_w;
        lvl.height = cur_h;
        lvl.pixel_count = cur_w * cur_h;
        lvl.byte_offset = offset;
        lvl.data.resize(lvl.pixel_count, 0.0f);
        pyramid_levels_.push_back(std::move(lvl));

        offset += cur_w * cur_h * sizeof(float);
        if (cur_w == 1 && cur_h == 1) break;
        cur_w = std::max(1U, cur_w >> 1);
        cur_h = std::max(1U, cur_h >> 1);
    }

    initialized_ = true;
    return true;
}

void HizReadbackEngine::Shutdown() {
    host_linear_buffer_.clear();
    pyramid_levels_.clear();
    initialized_ = false;
}

void HizReadbackEngine::PopulateDepthPattern(float base_depth) {
    if (!initialized_) return;

    // Generate a representative depth scene:
    // Reverse-Z: 1.0 = near plane, 0.0 = far plane
    // - Sky/far background: 0.05f
    // - Terrain gradient: 0.3f to 0.7f
    // - Prominent occluder in the center: 0.85f (castle wall / mountain)
    for (uint32_t y = 0; y < base_height_; ++y) {
        float ny = static_cast<float>(y) / static_cast<float>(base_height_);
        for (uint32_t x = 0; x < base_width_; ++x) {
            float nx = static_cast<float>(x) / static_cast<float>(base_width_);

            // Base ground terrain gradient
            float d = base_depth + (1.0f - ny) * 0.4f;

            // Center occluder (castle / large rock structure at UV [0.35..0.65, 0.30..0.70])
            if (nx >= 0.35f && nx <= 0.65f && ny >= 0.30f && ny <= 0.70f) {
                d = 0.85f; // Closer to camera (Reverse-Z near)
            }

            host_linear_buffer_[y * base_width_ + x] = std::clamp(d, 0.0f, 1.0f);
        }
    }

    BuildHierarchicalPyramid(true);
}

void HizReadbackEngine::BuildHierarchicalPyramid(bool reverse_z) {
    if (!initialized_ || pyramid_levels_.empty()) return;

    // Copy Mip 0 directly from linear host buffer
    std::memcpy(
        pyramid_levels_[0].data.data(),
        host_linear_buffer_.data(),
        host_linear_buffer_.size() * sizeof(float));

    // Downsample each successive mip level
    for (size_t m = 1; m < pyramid_levels_.size(); ++m) {
        const auto& parent = pyramid_levels_[m - 1];
        auto& current = pyramid_levels_[m];

        for (uint32_t y = 0; y < current.height; ++y) {
            for (uint32_t x = 0; x < current.width; ++x) {
                uint32_t px0 = x * 2;
                uint32_t py0 = y * 2;
                uint32_t px1 = std::min(px0 + 1, parent.width - 1);
                uint32_t py1 = std::min(py0 + 1, parent.height - 1);

                float d00 = parent.data[py0 * parent.width + px0];
                float d10 = parent.data[py0 * parent.width + px1];
                float d01 = parent.data[py1 * parent.width + px0];
                float d11 = parent.data[py1 * parent.width + px1];

                // In Reverse-Z, conservative occlusion depth is the minimum depth of the block
                // (i.e. furthest point of the occluders in that cell)
                float conservative_d = reverse_z
                    ? std::min({ d00, d10, d01, d11 })
                    : std::max({ d00, d10, d01, d11 });

                current.data[y * current.width + x] = conservative_d;
            }
        }
    }
}

float HizReadbackEngine::SampleDepth(float u, float v, uint32_t mip) const {
    if (!initialized_ || pyramid_levels_.empty()) return 0.0f;
    mip = std::min(mip, static_cast<uint32_t>(pyramid_levels_.size() - 1));

    const auto& lvl = pyramid_levels_[mip];
    float cu = std::clamp(u, 0.0f, 1.0f);
    float cv = std::clamp(v, 0.0f, 1.0f);

    uint32_t x = std::min(static_cast<uint32_t>(cu * lvl.width), lvl.width - 1);
    uint32_t y = std::min(static_cast<uint32_t>(cv * lvl.height), lvl.height - 1);

    return lvl.data[y * lvl.width + x];
}

bool HizReadbackEngine::QueryOcclusion(const HizBoundingBox& bbox, bool reverse_z) {
    if (!initialized_ || pyramid_levels_.empty()) return false;
    ++stats_.total_queries;

    // Project bounding box coordinates into normalized screen UV [0, 1]
    float u0 = std::clamp((bbox.min_x + 1.0f) * 0.5f, 0.0f, 1.0f);
    float u1 = std::clamp((bbox.max_x + 1.0f) * 0.5f, 0.0f, 1.0f);
    float v0 = std::clamp((bbox.min_y + 1.0f) * 0.5f, 0.0f, 1.0f);
    float v1 = std::clamp((bbox.max_y + 1.0f) * 0.5f, 0.0f, 1.0f);

    if (u0 > u1) std::swap(u0, u1);
    if (v0 > v1) std::swap(v0, v1);

    float box_w = (u1 - u0) * base_width_;
    float box_h = (v1 - v0) * base_height_;
    float max_dim = std::max(1.0f, std::max(box_w, box_h));

    // Choose mip level where bounding box footprint is ~1 to 2 pixels
    int mip_target = static_cast<int>(std::floor(std::log2(max_dim)));
    uint32_t mip = std::clamp(mip_target, 0, static_cast<int>(pyramid_levels_.size() - 1));

    // In Reverse-Z, closer objects have higher Z.
    // The closest point of this bounding box to the camera is max_z.
    float object_closest_z = reverse_z ? bbox.max_z : bbox.min_z;

    // Sample conservative depth at center and corners
    float d_mid = SampleDepth((u0 + u1) * 0.5f, (v0 + v1) * 0.5f, mip);
    float d_c00 = SampleDepth(u0, v0, mip);
    float d_c11 = SampleDepth(u1, v1, mip);

    float hiz_depth = reverse_z
        ? std::max({ d_mid, d_c00, d_c11 })
        : std::min({ d_mid, d_c00, d_c11 });

    // In Reverse-Z: if object_closest_z <= hiz_depth, the entire object is behind the occluder
    bool is_occluded = reverse_z
        ? (object_closest_z <= hiz_depth)
        : (object_closest_z >= hiz_depth);

    if (is_occluded) {
        ++stats_.occluded_count;
    } else {
        ++stats_.visible_count;
    }
    return is_occluded;
}

} // namespace yotei::graphics
