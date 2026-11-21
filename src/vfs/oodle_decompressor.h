#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <mutex>

namespace yotei::vfs {

// Function pointer prototype for Oodle Kraken decompression
typedef int64_t (*OodleLZ_Decompress_Fn)(
    const void* comp_buf,
    size_t comp_len,
    void* raw_buf,
    size_t raw_len,
    int fuzz_safe,
    int check_crc,
    int verbose,
    void* dst_base,
    size_t e,
    void* cb,
    void* cb_ctx,
    void* scratch,
    size_t scratch_size,
    int thread_phase);

class OodleDecompressor {
public:
    static OodleDecompressor& Instance();

    bool Initialize(const std::string& custom_dll_path = "");
    void Shutdown();

    [[nodiscard]] bool IsAvailable() const { return decompress_fn_ != nullptr; }
    [[nodiscard]] const std::string& GetLoadedDllPath() const { return loaded_path_; }

    // Decompress a raw Kraken block
    int64_t DecompressKraken(
        const void* comp_buf,
        size_t comp_len,
        void* raw_buf,
        size_t raw_len);

    // Decompress an entire or partial KCAP container stream (.xpps)
    bool DecompressKcapStream(
        const uint8_t* kcap_data,
        size_t kcap_size,
        uint32_t stream_index,
        std::vector<uint8_t>& out_decompressed);

private:
    OodleDecompressor() = default;
    ~OodleDecompressor();

    void* dll_handle_{nullptr};
    OodleLZ_Decompress_Fn decompress_fn_{nullptr};
    std::string loaded_path_{};
    mutable std::mutex mutex_{};
};

} // namespace yotei::vfs
