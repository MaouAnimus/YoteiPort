#include "graphics/xtbs_decoder.h"
#include <fstream>
#include <cstring>
#include <iostream>
#include <filesystem>

namespace yotei::graphics {

namespace {
constexpr uint8_t kSentinel[4] = { 0x13, 0xad, 0xdb, 0xba };

const uint8_t* FindSentinel(const uint8_t* start, const uint8_t* end) {
    if (end - start < 4) return nullptr;
    for (const uint8_t* p = start; p <= end - 4; ++p) {
        if (p[0] == kSentinel[0] && p[1] == kSentinel[1] &&
            p[2] == kSentinel[2] && p[3] == kSentinel[3]) {
            return p;
        }
    }
    return nullptr;
}
} // namespace

XtbsDecoder& XtbsDecoder::Instance() {
    static XtbsDecoder instance;
    return instance;
}

uint32_t XtbsDecoder::MapAgcFormatToVk(uint16_t agc_format) {
    switch (agc_format) {
        case 0x0600: return 133; // VK_FORMAT_BC1_RGBA_UNORM_BLOCK
        case 0x0900: return 139; // VK_FORMAT_BC4_UNORM_BLOCK
        case 0x0E00: return 145; // VK_FORMAT_BC7_UNORM_BLOCK
        case 0x0800: return 9;   // VK_FORMAT_R8_UNORM
        case 0x0002:
        case 0x1002:
        case 0x0000:
        default:
            return 37;           // VK_FORMAT_R8G8B8A8_UNORM
    }
}

const char* XtbsDecoder::GetFormatName(uint32_t vk_format) {
    switch (vk_format) {
        case 133: return "VK_FORMAT_BC1_RGBA_UNORM_BLOCK";
        case 139: return "VK_FORMAT_BC4_UNORM_BLOCK";
        case 145: return "VK_FORMAT_BC7_UNORM_BLOCK";
        case 9:   return "VK_FORMAT_R8_UNORM";
        case 37:  return "VK_FORMAT_R8G8B8A8_UNORM";
        default:  return "VK_FORMAT_UNKNOWN";
    }
}

bool XtbsDecoder::DecodeFromFile(const std::string& host_path, XtbsSurface& out_surface) {
    std::ifstream file(host_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return false;
    }

    out_surface.asset_name = std::filesystem::path(host_path).stem().string();
    return DecodeFromMemory(buffer.data(), buffer.size(), out_surface);
}

bool XtbsDecoder::DecodeFromMemory(const uint8_t* data, size_t size, XtbsSurface& out_surface) {
    if (!data || size < 64) return false;

    // Verify magic: 'XTBS'
    if (std::memcmp(data, "XTBS", 4) != 0) {
        return false;
    }

    const uint8_t* end = data + size;
    const uint8_t* s1 = FindSentinel(data, end);
    if (!s1) return false;

    const uint8_t* s2 = FindSentinel(s1 + 4, end);
    if (!s2) return false;

    size_t desc_size = static_cast<size_t>(s2 - (s1 + 4));
    if (desc_size < sizeof(XtbsDescriptor)) {
        return false;
    }

    const auto* desc = reinterpret_cast<const XtbsDescriptor*>(s1 + 4);
    out_surface.asset_hash = desc->asset_id_hash;
    out_surface.agc_format = desc->agc_format;
    out_surface.vk_format = MapAgcFormatToVk(desc->agc_format);
    out_surface.tile_mode = desc->tile_mode;
    out_surface.width = desc->width;
    out_surface.height = desc->height;
    out_surface.depth = desc->depth_or_array > 0 ? desc->depth_or_array : 1;
    out_surface.mip_levels = desc->mip_levels > 0 ? desc->mip_levels : 1;

    const uint8_t* payload_start = s2 + 4;
    size_t payload_len = static_cast<size_t>(end - payload_start);
    out_surface.payload.assign(payload_start, payload_start + payload_len);

    return true;
}

} // namespace yotei::graphics
