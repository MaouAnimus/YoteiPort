#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace yotei::graphics {

#pragma pack(push, 1)
struct XtbsDescriptor {
    uint32_t unk_desc_0;
    uint64_t asset_id_hash;
    uint16_t agc_format;
    uint8_t  tile_mode;
    uint8_t  swizzle_flags;
    uint16_t width;
    uint16_t height;
    uint16_t depth_or_array;
    uint16_t mip_levels;
};
#pragma pack(pop)

struct XtbsSurface {
    std::string asset_name;
    uint64_t asset_hash = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t depth = 1;
    uint32_t mip_levels = 1;
    uint16_t agc_format = 0;
    uint32_t vk_format = 0; // VkFormat
    uint8_t  tile_mode = 0;
    std::vector<uint8_t> payload;
};

class XtbsDecoder {
public:
    static XtbsDecoder& Instance();

    bool DecodeFromFile(const std::string& host_path, XtbsSurface& out_surface);
    bool DecodeFromMemory(const uint8_t* data, size_t size, XtbsSurface& out_surface);

    static uint32_t MapAgcFormatToVk(uint16_t agc_format);
    static const char* GetFormatName(uint32_t vk_format);

private:
    XtbsDecoder() = default;
};

} // namespace yotei::graphics
