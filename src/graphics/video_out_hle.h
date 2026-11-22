#pragma once
#include "graphics/smbs_decoder.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace yotei::graphics {

struct GpuLitVertex {
    float cx, cy, cz, cw; // Clip-space position (Location 0)
    float r, g, b, a;     // Lit vertex color (Location 1)
};

struct VideoOutBufferInfo {
    int32_t set_index = 0;
    int32_t buffer_index = 0;
    uint64_t guest_address = 0;
    uint64_t metadata_address = 0;
    uint32_t width = 1920;
    uint32_t height = 1080;
    uint32_t pitch = 1920 * 4;
    uint32_t format = 0;
    bool is_mapped = false;
};

struct VideoOutState {
    bool is_open = false;
    uint32_t width = 1920;
    uint32_t height = 1080;
    float refresh_rate = 60.0f;
    uint32_t flip_rate = 0;
    uint64_t flip_count = 0;
    uint32_t current_buffer_index = 0;
    std::vector<VideoOutBufferInfo> registered_buffers;
};

class VideoOutHleManager {
public:
    static VideoOutHleManager& Instance();

    bool Initialize(uint32_t width = 1920, uint32_t height = 1080,
                    const std::string& title = "Ghost of Yotei - Native PC Port (PPSA26344)");
    void PollEvents();
    bool SubmitFlip(int32_t handle, int32_t buffer_index, int32_t flip_mode, int64_t flip_arg);
    void Shutdown();

    bool IsWindowActive() const { return window_created_; }
    bool ShouldClose() const { return close_requested_; }
    void RequestClose() { close_requested_ = true; }
    uint64_t GetFlipCount() const { return state_.flip_count; }
    void SetActiveSceneGeometry(uint64_t index_buffer_handle, uint32_t index_count);
    void BindOrbitingSceneMesh(
        const std::vector<SmbsVertex>& vertices,
        uint64_t gpu_buffer_handle,
        void* host_mapped_ptr,
        uint64_t index_byte_offset,
        uint32_t index_count);
    void UpdateWindowTelemetryTitle(const std::string& telemetry_hud);
    void PrintLiveVideoOutBreakdown() const;
#ifdef _WIN32
    HWND GetHwnd() const { return hwnd_; }
#endif

    // HLE handlers for libSceVideoOut NIDs
    int32_t SceVideoOutOpen(int32_t user_id, int32_t bus_type, int32_t bus_index, uint64_t param);
    int32_t SceVideoOutClose(int32_t handle);
    int32_t SceVideoOutRegisterBuffers2(int32_t handle, int32_t set_index, int32_t buffer_index_start,
                                       uint64_t buffers_ptr, int32_t num_buffers, uint64_t attr_ptr);
    int32_t SceVideoOutSetBufferAttribute2(uint64_t attr, uint32_t pixel_format, uint32_t tiling_mode,
                                          uint32_t aspect_ratio, uint32_t width, uint32_t height, uint32_t pitch);
    int32_t SceVideoOutSubmitFlip(int32_t handle, int32_t buffer_index, int32_t flip_mode, int64_t flip_arg);
    int32_t SceVideoOutSetFlipRate(int32_t handle, int32_t flip_rate);
    int32_t SceVideoOutGetFlipStatus(int32_t handle, uint64_t status_out);
    int32_t SceVideoOutIsFlipPending(int32_t handle);
    int32_t SceVideoOutGetOutputStatus(int32_t handle, uint64_t status_out);
    int32_t SceVideoOutIsOutputSupported(int32_t handle, int32_t output_type);

    bool DispatchNid(const std::string& library, const std::string& nid,
                     const std::string& name,
                     uint64_t rdi, uint64_t rsi, uint64_t rdx,
                     uint64_t rcx, uint64_t r8, uint64_t r9,
                     uint64_t* ret);

private:
    VideoOutHleManager() = default;
    ~VideoOutHleManager();

    bool CreateHostWindow(uint32_t width, uint32_t height, const std::string& title);
    bool CreateVulkanSwapchain(uint32_t width, uint32_t height);
    void DestroyVulkanSwapchain();
    void UpdateOrbitingMeshVertices(uint64_t frame_idx);

    mutable std::mutex mutex_;
    VideoOutState state_{};
    bool window_created_ = false;
    bool swapchain_created_ = false;
    bool close_requested_ = false;

#ifdef _WIN32
    HWND hwnd_ = nullptr;
    HINSTANCE hinstance_ = nullptr;
#endif

    // Vulkan Swapchain resources (dynamically loaded)
    void* vk_surface_ = nullptr;
    void* vk_swapchain_ = nullptr;
    uint32_t swapchain_image_count_ = 0;
    std::vector<void*> swapchain_images_;
    std::vector<void*> swapchain_image_views_;
    void* vk_present_queue_ = nullptr;
    uint32_t present_queue_family_ = 0;
    uint64_t acquire_fence_ = 0;
    uint64_t active_scene_vb_ = 0;
    uint64_t active_scene_ib_ = 0;
    uint64_t active_scene_ib_offset_ = 0;
    uint32_t active_scene_index_count_ = 384;
    void* mapped_vtx_ptr_ = nullptr;
    std::vector<SmbsVertex> normalized_vertices_;
    std::unordered_map<std::string, uint64_t> fn_call_counts_;
    std::unordered_map<std::string, uint64_t> fn_last_rdi_;
    std::unordered_map<std::string, uint64_t> fn_last_rsi_;
};

} // namespace yotei::graphics
