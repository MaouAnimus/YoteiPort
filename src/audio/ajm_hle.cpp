#include "audio/ajm_hle.h"
#include <cstring>
#include <iostream>

namespace yotei::audio {

AjmHleManager& AjmHleManager::Instance() {
    static AjmHleManager instance;
    return instance;
}

int32_t AjmHleManager::Initialize(void* param) {
    (void)param;
    initialized_ = true;
    return SCE_AJM_OK;
}

int32_t AjmHleManager::Finalize() {
    std::lock_guard<std::mutex> lock(mutex_);
    instances_.clear();
    batches_.clear();
    initialized_ = false;
    return SCE_AJM_OK;
}

int32_t AjmHleManager::InstanceCreate(void* param, int32_t* out_instance) {
    (void)param;
    if (!out_instance) return SCE_AJM_ERROR_INVALID_PARAM;
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t id = next_instance_id_++;
    instances_[id] = true;
    *out_instance = id;
    return SCE_AJM_OK;
}

int32_t AjmHleManager::InstanceDestroy(int32_t instance) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = instances_.find(instance);
    if (it == instances_.end()) return SCE_AJM_ERROR_INVALID_ID;
    instances_.erase(it);
    return SCE_AJM_OK;
}

int32_t AjmHleManager::ModuleRegister(int32_t instance, uint32_t codec, void* param) {
    (void)instance;
    (void)codec;
    (void)param;
    return SCE_AJM_OK;
}

int32_t AjmHleManager::BatchInitialize(int32_t instance, void* batch_param, uint64_t* out_batch_id) {
    (void)batch_param;
    if (!out_batch_id) return SCE_AJM_ERROR_INVALID_PARAM;
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t bid = next_batch_id_++;
    SceAjmBatchInfo info{};
    info.batch_id = bid;
    info.instance_id = instance;
    info.completed = false;
    batches_[bid] = info;
    *out_batch_id = bid;
    return SCE_AJM_OK;
}

int32_t AjmHleManager::BatchStart(uint64_t batch_id, void* run_param) {
    (void)run_param;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = batches_.find(batch_id);
    if (it != batches_.end()) {
        it->second.completed = true;
        total_batches_processed_.fetch_add(1, std::memory_order_relaxed);
    }
    return SCE_AJM_OK;
}

int32_t AjmHleManager::BatchWait(uint64_t batch_id, uint32_t timeout_us) {
    (void)batch_id;
    (void)timeout_us;
    // In our HLE execution, batch jobs complete immediately on start
    return SCE_AJM_OK;
}

int32_t AjmHleManager::BatchErrorDump(uint64_t batch_id, void* dump_param) {
    (void)batch_id;
    (void)dump_param;
    return SCE_AJM_OK;
}

int32_t AjmHleManager::BatchJobGetStatistics(uint64_t batch_id, void* stats) {
    (void)batch_id;
    if (stats) {
        std::memset(stats, 0, 64);
    }
    return SCE_AJM_OK;
}

int32_t AjmHleManager::DecAt9ParseConfigData(const void* config_data, uint32_t size, void* parsed_info) {
    (void)config_data;
    (void)size;
    if (parsed_info) {
        // Fill basic ATRAC9 stereo info: 48000 Hz, 2 channels
        struct At9Info {
            uint32_t sample_rate;
            uint32_t channels;
            uint32_t frame_size;
            uint32_t superframe_size;
        };
        auto* info = reinterpret_cast<At9Info*>(parsed_info);
        info->sample_rate = 48000;
        info->channels = 2;
        info->frame_size = 256;
        info->superframe_size = 1024;
    }
    return SCE_AJM_OK;
}

} // namespace yotei::audio

