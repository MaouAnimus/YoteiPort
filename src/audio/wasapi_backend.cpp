#include "audio/wasapi_backend.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <avrt.h>
#include <functiondiscoverykeys_devpkey.h>
#endif

#include <iostream>
#include <algorithm>
#include <chrono>

namespace yotei::audio {

WasapiHostBackend& WasapiHostBackend::Instance() {
    static WasapiHostBackend instance;
    return instance;
}

WasapiHostBackend::~WasapiHostBackend() {
    Shutdown();
}

bool WasapiHostBackend::Initialize(uint32_t sample_rate, uint32_t channels) {
    if (initialized_) return true;

    // Allocate internal PCM ring buffer (1 second worth of samples)
    size_t total_samples = sample_rate * channels;
    ring_capacity_ = total_samples;
    ring_buffer_.assign(total_samples, 0.0f);
    ring_read_pos_ = 0;
    ring_write_pos_ = 0;

    // Attempt native WASAPI Shared Mode
    if (InitWasapi(sample_rate, channels)) {
        initialized_ = true;
        return true;
    }

    // Fallback cleanly to Null Audio Sink
    if (InitNullSink(sample_rate, channels)) {
        initialized_ = true;
        return true;
    }

    return false;
}

bool WasapiHostBackend::InitWasapi(uint32_t sample_rate, uint32_t channels) {
#ifdef _WIN32
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    // S_OK, S_FALSE, or RPC_E_CHANGED_MODE are acceptable

    IMMDeviceEnumerator* enumerator = nullptr;
    hr = CoCreateInstance(
        __uuidof(MMDeviceEnumerator),
        nullptr,
        CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator),
        reinterpret_cast<void**>(&enumerator));
    if (FAILED(hr) || !enumerator) {
        return false;
    }

    IMMDevice* device = nullptr;
    hr = enumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &device);
    enumerator->Release();
    if (FAILED(hr) || !device) {
        return false;
    }

    // Query friendly name of the active audio endpoint
    IPropertyStore* props = nullptr;
    if (SUCCEEDED(device->OpenPropertyStore(STGM_READ, &props)) && props) {
        PROPVARIANT name_var;
        PropVariantInit(&name_var);
        if (SUCCEEDED(props->GetValue(PKEY_Device_FriendlyName, &name_var))) {
            if (name_var.vt == VT_LPWSTR && name_var.pwszVal) {
                int len = WideCharToMultiByte(CP_UTF8, 0, name_var.pwszVal, -1, nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    std::string name(len - 1, 0);
                    WideCharToMultiByte(CP_UTF8, 0, name_var.pwszVal, -1, &name[0], len, nullptr, nullptr);
                    device_info_.device_name = name;
                }
            }
        }
        PropVariantClear(&name_var);
        props->Release();
    }

    IAudioClient* audio_client = nullptr;
    hr = device->Activate(
        __uuidof(IAudioClient),
        CLSCTX_ALL,
        nullptr,
        reinterpret_cast<void**>(&audio_client));
    if (FAILED(hr) || !audio_client) {
        device->Release();
        return false;
    }

    // Configure stereo IEEE float 48 kHz format
    WAVEFORMATEXTENSIBLE wfx{};
    wfx.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    wfx.Format.nChannels = static_cast<WORD>(channels);
    wfx.Format.nSamplesPerSec = sample_rate;
    wfx.Format.wBitsPerSample = 32;
    wfx.Format.nBlockAlign = (wfx.Format.nChannels * wfx.Format.wBitsPerSample) / 8;
    wfx.Format.nAvgBytesPerSec = wfx.Format.nSamplesPerSec * wfx.Format.nBlockAlign;
    wfx.Format.cbSize = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
    wfx.Samples.wValidBitsPerSample = 32;
    wfx.dwChannelMask = (channels == 2) ? (SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT) : SPEAKER_ALL;
    wfx.SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;

    WAVEFORMATEX* closest_match = nullptr;
    hr = audio_client->IsFormatSupported(
        AUDCLNT_SHAREMODE_SHARED,
        reinterpret_cast<const WAVEFORMATEX*>(&wfx),
        &closest_match);

    const WAVEFORMATEX* chosen_fmt = reinterpret_cast<const WAVEFORMATEX*>(&wfx);
    if (hr == S_FALSE && closest_match) {
        chosen_fmt = closest_match;
    } else if (FAILED(hr)) {
        if (closest_match) CoTaskMemFree(closest_match);
        audio_client->Release();
        device->Release();
        return false;
    }

    // Initialize in shared mode with 20ms buffer
    REFERENCE_TIME buffer_duration = 200000; // 20ms in 100ns units
    hr = audio_client->Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        0,
        buffer_duration,
        0,
        chosen_fmt,
        nullptr);
    if (closest_match) {
        CoTaskMemFree(closest_match);
        closest_match = nullptr;
    }
    if (FAILED(hr)) {
        audio_client->Release();
        device->Release();
        return false;
    }

    UINT32 buffer_frame_count = 0;
    audio_client->GetBufferSize(&buffer_frame_count);

    IAudioRenderClient* render_client = nullptr;
    hr = audio_client->GetService(
        __uuidof(IAudioRenderClient),
        reinterpret_cast<void**>(&render_client));
    if (FAILED(hr) || !render_client) {
        audio_client->Release();
        device->Release();
        return false;
    }

    audio_client_ = audio_client;
    render_client_ = render_client;
    audio_endpoint_ = device;

    device_info_.sample_rate = sample_rate;
    device_info_.channels = channels;
    device_info_.buffer_frames = buffer_frame_count;
    device_info_.is_null_sink = false;
    device_info_.is_initialized = true;

    // Start WASAPI playback
    audio_client->Start();

    running_.store(true, std::memory_order_release);
    render_thread_ = std::thread(&WasapiHostBackend::RenderLoop, this);
    return true;
#else
    return false;
#endif
}

bool WasapiHostBackend::InitNullSink(uint32_t sample_rate, uint32_t channels) {
    device_info_.device_name = "Host Null Audio Sink (Virtual Direct Playback)";
    device_info_.sample_rate = sample_rate;
    device_info_.channels = channels;
    device_info_.buffer_frames = 1024;
    device_info_.is_null_sink = true;
    device_info_.is_initialized = true;

    running_.store(true, std::memory_order_release);
    render_thread_ = std::thread(&WasapiHostBackend::NullSinkLoop, this);
    return true;
}

void WasapiHostBackend::RenderLoop() {
#ifdef _WIN32
    // Set thread to "Pro Audio" multimedia priority
    DWORD task_index = 0;
    HANDLE mm_handle = AvSetMmThreadCharacteristicsW(L"Pro Audio", &task_index);

    auto* audio_client = static_cast<IAudioClient*>(audio_client_);
    auto* render_client = static_cast<IAudioRenderClient*>(render_client_);

    const uint32_t channels = device_info_.channels;
    const uint32_t buffer_frames = device_info_.buffer_frames;

    while (running_.load(std::memory_order_acquire)) {
        UINT32 padding = 0;
        if (FAILED(audio_client->GetCurrentPadding(&padding))) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        UINT32 available_frames = (buffer_frames > padding) ? (buffer_frames - padding) : 0;
        if (available_frames > 0) {
            BYTE* dest_buffer = nullptr;
            if (SUCCEEDED(render_client->GetBuffer(available_frames, &dest_buffer)) && dest_buffer) {
                float* out_ptr = reinterpret_cast<float*>(dest_buffer);
                uint32_t frames_copied = 0;

                {
                    std::lock_guard<std::mutex> lock(ring_mutex_);
                    size_t samples_available = (ring_write_pos_ >= ring_read_pos_)
                        ? (ring_write_pos_ - ring_read_pos_)
                        : (ring_buffer_.size() - ring_read_pos_ + ring_write_pos_);
                    size_t frames_available = samples_available / channels;
                    frames_copied = static_cast<uint32_t>(std::min<size_t>(available_frames, frames_available));

                    for (uint32_t f = 0; f < frames_copied; ++f) {
                        for (uint32_t c = 0; c < channels; ++c) {
                            *out_ptr++ = ring_buffer_[ring_read_pos_];
                            ring_read_pos_ = (ring_read_pos_ + 1) % ring_buffer_.size();
                        }
                    }
                }

                // If underflow, fill remaining with silence
                if (frames_copied < available_frames) {
                    uint32_t silence_samples = (available_frames - frames_copied) * channels;
                    std::fill_n(out_ptr, silence_samples, 0.0f);
                }

                render_client->ReleaseBuffer(available_frames, (frames_copied == 0) ? AUDCLNT_BUFFERFLAGS_SILENT : 0);
                total_frames_rendered_.fetch_add(available_frames, std::memory_order_relaxed);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    if (mm_handle) {
        AvRevertMmThreadCharacteristics(mm_handle);
    }
#endif
}

void WasapiHostBackend::NullSinkLoop() {
    const uint32_t channels = device_info_.channels;
    const uint32_t frames_per_tick = device_info_.sample_rate / 100; // 10ms worth = 480 frames

    while (running_.load(std::memory_order_acquire)) {
        {
            std::lock_guard<std::mutex> lock(ring_mutex_);
            size_t samples_available = (ring_write_pos_ >= ring_read_pos_)
                ? (ring_write_pos_ - ring_read_pos_)
                : (ring_buffer_.size() - ring_read_pos_ + ring_write_pos_);
            size_t frames_available = samples_available / channels;
            size_t frames_to_consume = std::min<size_t>(frames_per_tick, frames_available);

            ring_read_pos_ = (ring_read_pos_ + frames_to_consume * channels) % ring_buffer_.size();
            total_frames_rendered_.fetch_add(frames_to_consume, std::memory_order_relaxed);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool WasapiHostBackend::PushPcmFloat(const float* pcm_data, uint32_t frame_count) {
    if (!initialized_ || !pcm_data || frame_count == 0) return false;
    const uint32_t channels = device_info_.channels;
    const size_t samples_to_write = frame_count * channels;

    std::lock_guard<std::mutex> lock(ring_mutex_);
    for (size_t i = 0; i < samples_to_write; ++i) {
        ring_buffer_[ring_write_pos_] = pcm_data[i];
        ring_write_pos_ = (ring_write_pos_ + 1) % ring_buffer_.size();
        if (ring_write_pos_ == ring_read_pos_) {
            // Buffer overflow: drop oldest sample
            ring_read_pos_ = (ring_read_pos_ + 1) % ring_buffer_.size();
        }
    }

    total_frames_submitted_.fetch_add(frame_count, std::memory_order_relaxed);
    return true;
}

bool WasapiHostBackend::PushPcmInt16(const int16_t* pcm_data, uint32_t frame_count) {
    if (!initialized_ || !pcm_data || frame_count == 0) return false;
    const uint32_t channels = device_info_.channels;
    const size_t total_samples = frame_count * channels;

    std::vector<float> converted(total_samples);
    constexpr float scale = 1.0f / 32768.0f;
    for (size_t i = 0; i < total_samples; ++i) {
        converted[i] = static_cast<float>(pcm_data[i]) * scale;
    }
    return PushPcmFloat(converted.data(), frame_count);
}

uint32_t WasapiHostBackend::GetCurrentQueueLevel() const {
    if (!initialized_) return 0;
    std::lock_guard<std::mutex> lock(ring_mutex_);
    size_t samples_available = (ring_write_pos_ >= ring_read_pos_)
        ? (ring_write_pos_ - ring_read_pos_)
        : (ring_buffer_.size() - ring_read_pos_ + ring_write_pos_);
    return static_cast<uint32_t>(samples_available / device_info_.channels);
}

void WasapiHostBackend::Shutdown() {
    if (!initialized_) return;

    running_.store(false, std::memory_order_release);
    if (render_thread_.joinable()) {
        render_thread_.join();
    }

#ifdef _WIN32
    if (audio_client_) {
        auto* client = static_cast<IAudioClient*>(audio_client_);
        client->Stop();
        client->Release();
        audio_client_ = nullptr;
    }
    if (render_client_) {
        auto* render = static_cast<IAudioRenderClient*>(render_client_);
        render->Release();
        render_client_ = nullptr;
    }
    if (audio_endpoint_) {
        auto* device = static_cast<IMMDevice*>(audio_endpoint_);
        device->Release();
        audio_endpoint_ = nullptr;
    }
    CoUninitialize();
#endif

    initialized_ = false;
    device_info_ = {};
}

} // namespace yotei::audio

