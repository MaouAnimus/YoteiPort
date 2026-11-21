#include "vfs/oodle_decompressor.h"
#include <iostream>
#include <filesystem>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::vfs {

OodleDecompressor& OodleDecompressor::Instance() {
    static OodleDecompressor instance;
    return instance;
}

OodleDecompressor::~OodleDecompressor() {
    Shutdown();
}

bool OodleDecompressor::Initialize(const std::string& custom_dll_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (decompress_fn_) return true;

    std::vector<std::string> candidate_paths;
    if (!custom_dll_path.empty()) {
        candidate_paths.push_back(custom_dll_path);
    }
    candidate_paths.push_back("PS5PKGTool-v1.3.0\\oo2core_9_win64.dll");
    candidate_paths.push_back("..\\Tools\\oo2core_9_win64.dll");
    candidate_paths.push_back("C:\\Users\\Alvaro\\Downloads\\Projects\\Tools\\oo2core_9_win64.dll");
    candidate_paths.push_back("oo2core_9_win64.dll");

    for (const auto& path_str : candidate_paths) {
        std::error_code ec;
        if (!std::filesystem::exists(path_str, ec)) continue;

#ifdef _WIN32
        HMODULE hMod = LoadLibraryA(path_str.c_str());
        if (hMod) {
            auto fn = reinterpret_cast<OodleLZ_Decompress_Fn>(
                GetProcAddress(hMod, "OodleLZ_Decompress"));
            if (fn) {
                dll_handle_ = hMod;
                decompress_fn_ = fn;
                loaded_path_ = std::filesystem::absolute(path_str).string();
                std::cout << "[+] Oodle Kraken Decompressor: LOADED (" 
                          << loaded_path_ << ")" << std::endl;
                return true;
            }
            FreeLibrary(hMod);
        }
#endif
    }

    std::cout << "[-] Oodle Kraken Decompressor: Not found (fallback passthrough mode enabled)" << std::endl;
    return false;
}

void OodleDecompressor::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
#ifdef _WIN32
    if (dll_handle_) {
        FreeLibrary(static_cast<HMODULE>(dll_handle_));
        dll_handle_ = nullptr;
    }
#endif
    decompress_fn_ = nullptr;
    loaded_path_.clear();
}

int64_t OodleDecompressor::DecompressKraken(
    const void* comp_buf,
    size_t comp_len,
    void* raw_buf,
    size_t raw_len) {
    if (!comp_buf || comp_len == 0 || !raw_buf || raw_len == 0) return -1;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!decompress_fn_) {
        // Fallback: raw memcpy if sizes match
        size_t copy_sz = (comp_len < raw_len) ? comp_len : raw_len;
        std::memcpy(raw_buf, comp_buf, copy_sz);
        return static_cast<int64_t>(copy_sz);
    }

    // Call official OodleLZ_Decompress with fuzzSafe=1, checkCRC=0, threadPhase=3
    int64_t res = decompress_fn_(
        comp_buf,
        comp_len,
        raw_buf,
        raw_len,
        1,      // fuzzSafe
        0,      // checkCRC
        0,      // verbose
        nullptr,// dstBase
        0,      // e
        nullptr,// cb
        nullptr,// cb_ctx
        nullptr,// scratch
        0,      // scratch_size
        3       // threadPhase
    );
    return res;
}

#pragma pack(push, 1)
struct KcapStreamDescriptor {
    uint32_t stream_type;
    uint32_t stream_size;
    uint64_t stream_offset;
    uint64_t reserved;
    uint64_t stream_id;
    uint64_t block_count;
};

struct KcapBlockDescriptor {
    uint32_t compressed_size;
    uint32_t relative_offset;
    uint32_t flags_and_type;
};
#pragma pack(pop)

bool OodleDecompressor::DecompressKcapStream(
    const uint8_t* kcap_data,
    size_t kcap_size,
    uint32_t stream_index,
    std::vector<uint8_t>& out_decompressed) {
    if (!kcap_data || kcap_size < 0x80) return false;

    // Check Magic: 'KCAP'
    if (std::memcmp(kcap_data, "KCAP", 4) != 0) {
        return false;
    }

    uint32_t payload_off = *reinterpret_cast<const uint32_t*>(kcap_data + 0x48);
    uint64_t stream_count = *reinterpret_cast<const uint64_t*>(kcap_data + 0x58);

    if (stream_index >= stream_count) return false;

    // Stream descriptors start at 0x80 or 0x90
    size_t stream_desc_offset = 0x90;
    if (stream_desc_offset + sizeof(KcapStreamDescriptor) * stream_count > kcap_size) {
        stream_desc_offset = 0x80;
    }

    const auto* streams = reinterpret_cast<const KcapStreamDescriptor*>(kcap_data + stream_desc_offset);
    const auto& s = streams[stream_index];

    // Read block descriptors
    size_t block_desc_offset = stream_desc_offset + sizeof(KcapStreamDescriptor) * stream_count;
    if (block_desc_offset + sizeof(KcapBlockDescriptor) * s.block_count > kcap_size) {
        return false;
    }

    const auto* blocks = reinterpret_cast<const KcapBlockDescriptor*>(kcap_data + block_desc_offset);
    out_decompressed.clear();
    out_decompressed.reserve(s.stream_size > 0 ? s.stream_size : 65536 * s.block_count);

    size_t block_uncomp_size = 65536; // Default Sucker Punch block size: 64 KiB
    std::vector<uint8_t> block_buf(block_uncomp_size);

    for (uint64_t i = 0; i < s.block_count; ++i) {
        const auto& b = blocks[i];
        size_t src_offset = payload_off + b.relative_offset;
        if (src_offset + b.compressed_size > kcap_size) {
            break;
        }

        const uint8_t* src_ptr = kcap_data + src_offset;
        // Check if block is Kraken-compressed:
        // Flag 0x20, or first byte is 0x8C, or compressed_size < block_uncomp_size
        bool is_compressed = (b.flags_and_type & 0x20) || (b.compressed_size < block_uncomp_size && src_ptr[0] == 0x8c);

        if (is_compressed && decompress_fn_) {
            int64_t decomp_len = DecompressKraken(
                src_ptr,
                b.compressed_size,
                block_buf.data(),
                block_uncomp_size);
            if (decomp_len > 0) {
                out_decompressed.insert(out_decompressed.end(), block_buf.begin(), block_buf.begin() + decomp_len);
            } else {
                // Passthrough on decompression error
                out_decompressed.insert(out_decompressed.end(), src_ptr, src_ptr + b.compressed_size);
            }
        } else {
            // Raw block
            out_decompressed.insert(out_decompressed.end(), src_ptr, src_ptr + b.compressed_size);
        }
    }

    return !out_decompressed.empty();
}

} // namespace yotei::vfs
