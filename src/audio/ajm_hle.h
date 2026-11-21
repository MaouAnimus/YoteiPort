#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <atomic>

namespace yotei::audio {

constexpr int32_t SCE_AJM_OK = 0;
constexpr int32_t SCE_AJM_ERROR_INVALID_PARAM = static_cast<int32_t>(0x802B0002U);
constexpr int32_t SCE_AJM_ERROR_INVALID_ID    = static_cast<int32_t>(0x802B0003U);

enum SceAjmCodecType : uint32_t {
    SCE_AJM_CODEC_AT9  = 1,
    SCE_AJM_CODEC_MP3  = 2,
    SCE_AJM_CODEC_AAC  = 3,
};

struct SceAjmBatchInfo {
    uint64_t batch_id{0};
    int32_t instance_id{0};
    bool completed{false};
};

class AjmHleManager {
public:
    static AjmHleManager& Instance();

    int32_t Initialize(void* param);
    int32_t Finalize();

    int32_t InstanceCreate(void* param, int32_t* out_instance);
    int32_t InstanceDestroy(int32_t instance);
    int32_t ModuleRegister(int32_t instance, uint32_t codec, void* param);

    int32_t BatchInitialize(int32_t instance, void* batch_param, uint64_t* out_batch_id);
    int32_t BatchStart(uint64_t batch_id, void* run_param);
    int32_t BatchWait(uint64_t batch_id, uint32_t timeout_us);
    int32_t BatchErrorDump(uint64_t batch_id, void* dump_param);
    int32_t BatchJobGetStatistics(uint64_t batch_id, void* stats);

    int32_t DecAt9ParseConfigData(const void* config_data, uint32_t size, void* parsed_info);

    [[nodiscard]] bool IsInitialized() const { return initialized_; }
    [[nodiscard]] uint64_t GetTotalBatchesProcessed() const { return total_batches_processed_.load(); }

private:
    AjmHleManager() = default;
    ~AjmHleManager() = default;

    bool initialized_{false};
    mutable std::mutex mutex_{};
    int32_t next_instance_id_{1};
    uint64_t next_batch_id_{1};
    std::atomic<uint64_t> total_batches_processed_{0};

    std::unordered_map<int32_t, bool> instances_{};
    std::unordered_map<uint64_t, SceAjmBatchInfo> batches_{};
};

} // namespace yotei::audio

