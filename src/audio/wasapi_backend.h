#pragma once

#include <cstdint>
#include <string>
#include <atomic>
#include <vector>
#include <mutex>
#include <thread>

namespace yotei::audio {

struct AudioDeviceInfo {
    std::string device_name = "None";
    uint32_t sample_rate = 48000;
    uint32_t channels = 2;
    uint32_t buffer_frames = 0;
    bool is_null_sink = false;
    bool is_initialized = false;
};

class WasapiHostBackend {
public:
    static WasapiHostBackend& Instance();

    bool Initialize(uint32_t sample_rate = 48000, uint32_t channels = 2);
    void Shutdown();

    // Push interleaved PCM float data [L, R, L, R, ...]
    bool PushPcmFloat(const float* pcm_data, uint32_t frame_count);

    // Push interleaved PCM 16-bit integer data [L, R, L, R, ...]
    bool PushPcmInt16(const int16_t* pcm_data, uint32_t frame_count);

    [[nodiscard]] const AudioDeviceInfo& GetDeviceInfo() const { return device_info_; }
    [[nodiscard]] bool IsInitialized() const { return initialized_; }
    [[nodiscard]] uint64_t GetTotalFramesSubmitted() const { return total_frames_submitted_.load(); }
    [[nodiscard]] uint64_t GetTotalFramesRendered() const { return total_frames_rendered_.load(); }
    [[nodiscard]] uint32_t GetCurrentQueueLevel() const;

private:
    WasapiHostBackend() = default;
    ~WasapiHostBackend();

    bool InitWasapi(uint32_t sample_rate, uint32_t channels);
    bool InitNullSink(uint32_t sample_rate, uint32_t channels);
    void RenderLoop();
    void NullSinkLoop();

    bool initialized_{false};
    AudioDeviceInfo device_info_{};

    std::atomic<bool> running_{false};
    std::thread render_thread_{};

    // Internal lock-free or mutex-guarded ring buffer
    mutable std::mutex ring_mutex_{};
    std::vector<float> ring_buffer_{};
    size_t ring_read_pos_{0};
    size_t ring_write_pos_{0};
    size_t ring_capacity_{48000 * 4}; // ~1 second buffer at 48 kHz stereo

    std::atomic<uint64_t> total_frames_submitted_{0};
    std::atomic<uint64_t> total_frames_rendered_{0};

    // WASAPI COM pointers kept as void* to isolate Windows headers
    void* audio_client_{nullptr};
    void* render_client_{nullptr};
    void* audio_endpoint_{nullptr};
};

} // namespace yotei::audio
