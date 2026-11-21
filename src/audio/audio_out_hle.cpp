#include "audio/audio_out_hle.h"
#include "audio/wasapi_backend.h"
#include <cstring>
#include <iostream>

namespace yotei::audio {

AudioOut2HleManager &AudioOut2HleManager::Instance() {
  static AudioOut2HleManager instance;
  return instance;
}

bool AudioOut2HleManager::Initialize() {
  if (initialized_)
    return true;
  auto &wasapi = WasapiHostBackend::Instance();
  wasapi.Initialize(48000, 2);
  initialized_ = true;
  return true;
}

void AudioOut2HleManager::Shutdown() {
  if (!initialized_)
    return;
  std::lock_guard<std::mutex> lock(state_mutex_);
  ports_.clear();
  contexts_.clear();
  WasapiHostBackend::Instance().Shutdown();
  initialized_ = false;
}

int32_t AudioOut2HleManager::PortCreate(const char *name, uint32_t port_type,
                                        uint32_t param, int32_t *out_handle) {
  if (!out_handle)
    return SCE_AUDIO_OUT_ERROR_INVALID_PARAM;
  std::lock_guard<std::mutex> lock(state_mutex_);

  int32_t id = next_port_id_++;
  SceAudioOutPortConfig cfg{};
  cfg.name = name ? name : "AudioPort_Default";
  cfg.port_type = port_type;
  cfg.param = param;
  cfg.sample_rate = 48000;
  cfg.channels = (port_type == SCE_AUDIO_OUT_PORT_TYPE_MAIN) ? 2 : 2;
  cfg.volume = 100;
  cfg.paused = false;

  ports_[id] = cfg;
  *out_handle = id;
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::PortDestroy(int32_t handle) {
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = ports_.find(handle);
  if (it == ports_.end())
    return SCE_AUDIO_OUT_ERROR_INVALID_HANDLE;
  ports_.erase(it);
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::PortGetState(int32_t handle, void *state) {
  if (!state)
    return SCE_AUDIO_OUT_ERROR_INVALID_PARAM;
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = ports_.find(handle);
  if (it == ports_.end())
    return SCE_AUDIO_OUT_ERROR_INVALID_HANDLE;

  // SceAudioOutPortState structure: uint32_t status, uint32_t volume, etc.
  struct SceAudioOutPortState {
    uint32_t status;
    uint32_t volume;
    uint32_t reserved[6];
  };
  auto *s = reinterpret_cast<SceAudioOutPortState *>(state);
  s->status = it->second.paused ? 0 : 1;
  s->volume = static_cast<uint32_t>(it->second.volume);
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::ContextCreate(int32_t port_handle, void *param,
                                           int32_t *out_context) {
  if (!out_context)
    return SCE_AUDIO_OUT_ERROR_INVALID_PARAM;
  std::lock_guard<std::mutex> lock(state_mutex_);

  int32_t id = next_context_id_++;
  SceAudioOutContextConfig cfg{};
  cfg.port_handle = port_handle;
  cfg.format = SCE_AUDIO_OUT_PARAM_FORMAT_FLOAT_STEREO;
  cfg.grain = 256;

  if (param) {
    // Read format parameter if valid
    const auto *p = reinterpret_cast<const uint32_t *>(param);
    cfg.format = p[0];
    if (p[1] > 0)
      cfg.grain = p[1];
  }

  contexts_[id] = cfg;
  *out_context = id;
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::ContextDestroy(int32_t context) {
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = contexts_.find(context);
  if (it == contexts_.end())
    return SCE_AUDIO_OUT_ERROR_INVALID_HANDLE;
  contexts_.erase(it);
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::ContextQueryMemory(void *param,
                                                uint64_t *out_size) {
  (void)param;
  if (!out_size)
    return SCE_AUDIO_OUT_ERROR_INVALID_PARAM;
  // Typical SceAudioOut2 context working memory: 64 KiB
  *out_size = 65536ULL;
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::ContextPush(int32_t context, const void *pcm,
                                         uint32_t sample_count, uint64_t tag) {
  if (!pcm || sample_count == 0)
    return SCE_AUDIO_OUT_OK;

  SceAudioOutContextConfig *ctx = nullptr;
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto it = contexts_.find(context);
    if (it != contexts_.end()) {
      ctx = &it->second;
      ctx->last_tag = tag;
      ctx->total_pushed_frames += sample_count;
    }
}

// Route audio directly to host WASAPI backend
auto &wasapi = WasapiHostBackend::Instance();
if (ctx && ctx->format == SCE_AUDIO_OUT_PARAM_FORMAT_S16_STEREO) {
  wasapi.PushPcmInt16(reinterpret_cast<const int16_t *>(pcm), sample_count);
} else {
  wasapi.PushPcmFloat(reinterpret_cast<const float *>(pcm), sample_count);
}

return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::ContextGetQueueLevel(int32_t context,
                                                  uint32_t *out_level) {
  if (!out_level)
    return SCE_AUDIO_OUT_ERROR_INVALID_PARAM;
  (void)context;
  *out_level = WasapiHostBackend::Instance().GetCurrentQueueLevel();
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::ContextResetParam(int32_t context, void *param) {
  (void)context;
  (void)param;
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::UserCreate(void *param, int32_t *out_user) {
  (void)param;
  if (!out_user)
    return SCE_AUDIO_OUT_ERROR_INVALID_PARAM;
  std::lock_guard<std::mutex> lock(state_mutex_);
  *out_user = next_user_id_++;
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::SetVolume(int32_t handle, int32_t volume) {
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = ports_.find(handle);
  if (it != ports_.end()) {
    it->second.volume = volume;
  }
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::GetVolume(int32_t handle, int32_t *out_volume) {
  if (!out_volume)
    return SCE_AUDIO_OUT_ERROR_INVALID_PARAM;
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = ports_.find(handle);
  if (it != ports_.end()) {
    *out_volume = it->second.volume;
  } else {
    *out_volume = 100;
  }
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::Pause(int32_t handle) {
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = ports_.find(handle);
  if (it != ports_.end()) {
    it->second.paused = true;
  }
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::Resume(int32_t handle) {
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = ports_.find(handle);
  if (it != ports_.end()) {
    it->second.paused = false;
  }
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::Set3DLatency(int32_t handle, uint32_t latency_ms) {
  (void)handle;
  (void)latency_ms;
  return SCE_AUDIO_OUT_OK;
}

int32_t AudioOut2HleManager::MasteringInit(void *param) {
  (void)param;
  return SCE_AUDIO_OUT_OK;
}

size_t AudioOut2HleManager::GetActivePortCount() const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return ports_.size();
}

size_t AudioOut2HleManager::GetActiveContextCount() const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return contexts_.size();
}

} // namespace yotei::audio
