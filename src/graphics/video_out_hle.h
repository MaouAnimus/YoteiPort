#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::graphics {

struct VideoOutBufferInfo {
    uint64_t guest_address = 0;
    uint32_t width = 1920;
    uint32_t height = 1080;
    uint32_t pitch = 1920 * 4;
    uint32_t format = 0;
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
    uint64_t GetFlipCount() const { return state_.flip_count; }
#ifdef _WIN32
    HWND GetHwnd() const { return hwnd_; }
#endif

    // HLE handlers for libSceVideoOut NIDs
    int32_t SceVideoOutOpen(int32_t user_id, int32_t bus_type, int32_t bus_index, uint64_t param);
    int32_t SceVideoOutClose(int32_t handle);
    int32_t SceVideoOutRegisterBuffers2(int32_t handle, int32_t start_index, uint64_t addresses,
                                       int32_t num_buffers, uint64_t attr);
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

    mutable std::mutex mutex_;
    VideoOutState state_{};
    bool window_created_ = false;
    bool swapchain_created_ = false;

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
};

} // namespace yotei::graphics
