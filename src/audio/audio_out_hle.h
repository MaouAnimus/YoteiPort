#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yotei::audio {

constexpr int32_t SCE_AUDIO_OUT_OK = 0;
constexpr int32_t SCE_AUDIO_OUT_ERROR_INVALID_HANDLE =
    static_cast<int32_t>(0x80260002U);
constexpr int32_t SCE_AUDIO_OUT_ERROR_INVALID_PARAM =
    static_cast<int32_t>(0x80260004U);
constexpr int32_t SCE_AUDIO_OUT_ERROR_OUT_OF_MEMORY =
    static_cast<int32_t>(0x80260005U);

enum SceAudioOutPortType : uint32_t {
  SCE_AUDIO_OUT_PORT_TYPE_MAIN = 0,
  SCE_AUDIO_OUT_PORT_TYPE_PADSPKR = 1,
  SCE_AUDIO_OUT_PORT_TYPE_VOICE = 2,
};

enum SceAudioOutParamFormat : uint32_t {
  SCE_AUDIO_OUT_PARAM_FORMAT_S16_STEREO = 0,
  SCE_AUDIO_OUT_PARAM_FORMAT_FLOAT_STEREO = 2,
  SCE_AUDIO_OUT_PARAM_FORMAT_FLOAT_7POINT1 = 3,
};

struct SceAudioOutPortConfig {
  std::string name;
  uint32_t port_type{SCE_AUDIO_OUT_PORT_TYPE_MAIN};
  uint32_t param{0};
  uint32_t sample_rate{48000};
  uint32_t channels{2};
  int32_t volume{100};
  bool paused{false};
};

struct SceAudioOutContextConfig {
    int32_t port_handle{0};
    uint32_t format{SCE_AUDIO_OUT_PARAM_FORMAT_FLOAT_STEREO};
    uint32_t grain{256};
    uint64_t total_pushed_frames{0};
    uint64_t last_tag{0};
};

class AudioOut2HleManager {
public:
  static AudioOut2HleManager &Instance();

  bool Initialize();
  void Shutdown();

  // libSceAudioOut2 API implementations
  int32_t PortCreate(const char *name, uint32_t port_type, uint32_t param,
                     int32_t *out_handle);
  int32_t PortDestroy(int32_t handle);
  int32_t PortGetState(int32_t handle, void *state);

  int32_t ContextCreate(int32_t port_handle, void *param, int32_t *out_context);
  int32_t ContextDestroy(int32_t context);
  int32_t ContextQueryMemory(void *param, uint64_t *out_size);
  int32_t ContextPush(int32_t context, const void *pcm, uint32_t sample_count,
                      uint64_t tag);
  int32_t ContextGetQueueLevel(int32_t context, uint32_t *out_level);
  int32_t ContextResetParam(int32_t context, void *param);

  int32_t UserCreate(void *param, int32_t *out_user);
  int32_t SetVolume(int32_t handle, int32_t volume);
  int32_t GetVolume(int32_t handle, int32_t *out_volume);
  int32_t Pause(int32_t handle);
  int32_t Resume(int32_t handle);
  int32_t Set3DLatency(int32_t handle, uint32_t latency_ms);
  int32_t MasteringInit(void *param);

  [[nodiscard]] bool IsInitialized() const { return initialized_; }
  [[nodiscard]] size_t GetActivePortCount() const;
  [[nodiscard]] size_t GetActiveContextCount() const;

private:
  AudioOut2HleManager() = default;
  ~AudioOut2HleManager() = default;

  bool initialized_{false};
  mutable std::mutex state_mutex_{};

  int32_t next_port_id_{1};
  int32_t next_context_id_{1};
  int32_t next_user_id_{1};

  std::unordered_map<int32_t, SceAudioOutPortConfig> ports_{};
  std::unordered_map<int32_t, SceAudioOutContextConfig> contexts_{};
};

} // namespace yotei::audio
