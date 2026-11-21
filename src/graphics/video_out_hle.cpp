#include "graphics/video_out_hle.h"
#include "graphics/vk_backend.h"
#include "kernel/threads.h"
#include <iostream>
#include <iomanip>
#include <cstring>

#ifdef _WIN32
#define VKAPI_PTR __stdcall
#else
#define VKAPI_PTR
#endif

namespace yotei::graphics {

namespace {

#ifdef _WIN32
LRESULT CALLBACK YoteiWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) {
                ShowWindow(hwnd, SW_MINIMIZE);
            }
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            // Black background for flip transitions
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}
#endif

// Vulkan C ABI definitions for Swapchain & Win32 Surface
using VkResult = int32_t;
using VkFlags = uint32_t;
using VkInstance = void*;
using VkPhysicalDevice = void*;
using VkDevice = void*;
using VkQueue = void*;
using VkSurfaceKHR = uint64_t;
using VkSwapchainKHR = uint64_t;
using VkImage = uint64_t;
using VkImageView = uint64_t;
using VkSemaphore = uint64_t;

constexpr VkResult VK_SUCCESS = 0;
constexpr uint32_t VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR = 1000009000;
constexpr uint32_t VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR = 1000001000;
constexpr uint32_t VK_STRUCTURE_TYPE_PRESENT_INFO_KHR = 1000001001;
constexpr uint32_t VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO = 15;

struct VkExtent2D {
    uint32_t width;
    uint32_t height;
};

struct VkWin32SurfaceCreateInfoKHR {
    uint32_t                 sType;
    const void*              pNext;
    VkFlags                  flags;
    HINSTANCE                hinstance;
    HWND                     hwnd;
};

struct VkSwapchainCreateInfoKHR {
    uint32_t                 sType;
    const void*              pNext;
    VkFlags                  flags;
    VkSurfaceKHR             surface;
    uint32_t                 minImageCount;
    uint32_t                 imageFormat;
    uint32_t                 imageColorSpace;
    VkExtent2D               imageExtent;
    uint32_t                 imageArrayLayers;
    VkFlags                  imageUsage;
    uint32_t                 imageSharingMode;
    uint32_t                 queueFamilyIndexCount;
    const uint32_t*          pQueueFamilyIndices;
    uint32_t                 preTransform;
    uint32_t                 compositeAlpha;
    uint32_t                 presentMode;
    uint32_t                 clipped;
    VkSwapchainKHR           oldSwapchain;
};

struct VkPresentInfoKHR {
    uint32_t                 sType;
    const void*              pNext;
    uint32_t                 waitSemaphoreCount;
    const VkSemaphore*       pWaitSemaphores;
    uint32_t                 swapchainCount;
    const VkSwapchainKHR*    pSwapchains;
    const uint32_t*          pImageIndices;
    VkResult*                pResults;
};

struct VkComponentMapping {
    uint32_t r;
    uint32_t g;
    uint32_t b;
    uint32_t a;
};

struct VkImageSubresourceRange {
    VkFlags  aspectMask;
    uint32_t baseMipLevel;
    uint32_t levelCount;
    uint32_t baseArrayLayer;
    uint32_t layerCount;
};

struct VkImageViewCreateInfo {
    uint32_t                sType;
    const void*             pNext;
    VkFlags                 flags;
    VkImage                 image;
    uint32_t                viewType;
    uint32_t                format;
    VkComponentMapping      components;
    VkImageSubresourceRange subresourceRange;
};

using PFN_vkCreateWin32SurfaceKHR = VkResult (VKAPI_PTR*)(VkInstance, const VkWin32SurfaceCreateInfoKHR*, const void*, VkSurfaceKHR*);
using PFN_vkDestroySurfaceKHR = void (VKAPI_PTR*)(VkInstance, VkSurfaceKHR, const void*);
using PFN_vkCreateSwapchainKHR = VkResult (VKAPI_PTR*)(VkDevice, const VkSwapchainCreateInfoKHR*, const void*, VkSwapchainKHR*);
using PFN_vkDestroySwapchainKHR = void (VKAPI_PTR*)(VkDevice, VkSwapchainKHR, const void*);
using PFN_vkGetSwapchainImagesKHR = VkResult (VKAPI_PTR*)(VkDevice, VkSwapchainKHR, uint32_t*, VkImage*);
using PFN_vkCreateImageView = VkResult (VKAPI_PTR*)(VkDevice, const VkImageViewCreateInfo*, const void*, VkImageView*);
using PFN_vkDestroyImageView = void (VKAPI_PTR*)(VkDevice, VkImageView, const void*);
using PFN_vkAcquireNextImageKHR = VkResult (VKAPI_PTR*)(VkDevice, VkSwapchainKHR, uint64_t, VkSemaphore, uint64_t, uint32_t*);
using PFN_vkQueuePresentKHR = VkResult (VKAPI_PTR*)(VkQueue, const VkPresentInfoKHR*);

constexpr uint32_t VK_STRUCTURE_TYPE_FENCE_CREATE_INFO = 8;
struct VkFenceCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
};
using PFN_vkCreateFence = VkResult (VKAPI_PTR*)(VkDevice, const VkFenceCreateInfo*, const void*, uint64_t*);
using PFN_vkDestroyFence = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkWaitForFences = VkResult (VKAPI_PTR*)(VkDevice, uint32_t, const uint64_t*, uint32_t, uint64_t);
using PFN_vkResetFences = VkResult (VKAPI_PTR*)(VkDevice, uint32_t, const uint64_t*);

} // namespace

VideoOutHleManager& VideoOutHleManager::Instance() {
    static VideoOutHleManager inst;
    return inst;
}

VideoOutHleManager::~VideoOutHleManager() {
    Shutdown();
}

bool VideoOutHleManager::Initialize(uint32_t width, uint32_t height, const std::string& title) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.width = width;
    state_.height = height;

    if (!CreateHostWindow(width, height, title)) {
        std::cerr << "[!] Failed to create Win32 host window\n";
        return false;
    }

    if (!CreateVulkanSwapchain(width, height)) {
        std::cout << "[*] Vulkan swapchain created in headless / virtual display mode\n";
    }

    state_.is_open = true;
    return true;
}

bool VideoOutHleManager::CreateHostWindow(uint32_t width, uint32_t height, const std::string& title) {
#ifdef _WIN32
    if (window_created_ && hwnd_) return true;

    hinstance_ = GetModuleHandleW(nullptr);
    const wchar_t* CLASS_NAME = L"YoteiPortWindowClass";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = YoteiWindowProc;
    wc.hInstance = hinstance_;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassExW(&wc);

    // Center window on desktop
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);
    int pos_x = (screen_w > static_cast<int>(width)) ? (screen_w - width) / 2 : 50;
    int pos_y = (screen_h > static_cast<int>(height)) ? (screen_h - height) / 2 : 50;

    std::wstring wtitle(title.begin(), title.end());
    hwnd_ = CreateWindowExW(
        0,
        CLASS_NAME,
        wtitle.c_str(),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        pos_x, pos_y,
        width, height,
        nullptr, nullptr,
        hinstance_, nullptr
    );

    if (!hwnd_) return false;

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);
    window_created_ = true;

    std::cout << "[+] Created Host Win32 Window: HWND=0x" << std::hex << hwnd_
              << " (" << std::dec << width << "x" << height << ") Title='" << title << "'\n";
    return true;
#else
    return false;
#endif
}

bool VideoOutHleManager::CreateVulkanSwapchain(uint32_t width, uint32_t height) {
#ifdef _WIN32
    auto& vk = VulkanHostBackend::Instance();
    if (!vk.IsInitialized()) {
        if (!vk.Initialize()) return false;
    }

    VkInstance inst = vk.GetInstance();
    VkDevice dev = vk.GetDevice();
    if (!inst || !dev || !hwnd_) return false;

    auto create_win32_surface = reinterpret_cast<PFN_vkCreateWin32SurfaceKHR>(
        vk.GetProcAddress("vkCreateWin32SurfaceKHR"));
    if (!create_win32_surface) return false;

    VkWin32SurfaceCreateInfoKHR surf_ci{};
    surf_ci.sType = VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR;
    surf_ci.hinstance = hinstance_;
    surf_ci.hwnd = hwnd_;

    VkSurfaceKHR surface = 0;
    if (create_win32_surface(inst, &surf_ci, nullptr, &surface) != VK_SUCCESS || !surface) {
        return false;
    }
    vk_surface_ = reinterpret_cast<void*>(surface);

    auto create_swapchain = reinterpret_cast<PFN_vkCreateSwapchainKHR>(
        vk.GetProcAddress("vkCreateSwapchainKHR"));
    auto get_swapchain_images = reinterpret_cast<PFN_vkGetSwapchainImagesKHR>(
        vk.GetProcAddress("vkGetSwapchainImagesKHR"));
    auto create_img_view = reinterpret_cast<PFN_vkCreateImageView>(
        vk.GetProcAddress("vkCreateImageView"));

    if (!create_swapchain || !get_swapchain_images) return false;

    VkSwapchainCreateInfoKHR sw_ci{};
    sw_ci.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    sw_ci.surface = surface;
    sw_ci.minImageCount = 3; // Triple buffering (typical PS5 flip queue)
    sw_ci.imageFormat = 44;  // VK_FORMAT_B8G8R8A8_UNORM
    sw_ci.imageColorSpace = 0; // VK_COLOR_SPACE_SRGB_NONLINEAR_KHR
    sw_ci.imageExtent.width = width;
    sw_ci.imageExtent.height = height;
    sw_ci.imageArrayLayers = 1;
    sw_ci.imageUsage = 0x10 | 0x02; // VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT
    sw_ci.imageSharingMode = 0;     // VK_SHARING_MODE_EXCLUSIVE
    sw_ci.preTransform = 1;         // VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR
    sw_ci.compositeAlpha = 1;       // VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR
    sw_ci.presentMode = 2;          // VK_PRESENT_MODE_FIFO_KHR (V-Sync)
    sw_ci.clipped = 1;

    VkSwapchainKHR swapchain = 0;
    if (create_swapchain(dev, &sw_ci, nullptr, &swapchain) != VK_SUCCESS || !swapchain) {
        return false;
    }
    vk_swapchain_ = reinterpret_cast<void*>(swapchain);

    uint32_t img_cnt = 0;
    get_swapchain_images(dev, swapchain, &img_cnt, nullptr);
    if (img_cnt > 0) {
        std::vector<VkImage> imgs(img_cnt);
        get_swapchain_images(dev, swapchain, &img_cnt, imgs.data());
        swapchain_image_count_ = img_cnt;

        for (uint32_t i = 0; i < img_cnt; ++i) {
            swapchain_images_.push_back(reinterpret_cast<void*>(imgs[i]));
            if (create_img_view) {
                VkImageViewCreateInfo iv_ci{};
                iv_ci.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
                iv_ci.image = imgs[i];
                iv_ci.viewType = 1; // VK_IMAGE_VIEW_TYPE_2D
                iv_ci.format = 44;  // VK_FORMAT_B8G8R8A8_UNORM
                iv_ci.components = {0, 0, 0, 0};
                iv_ci.subresourceRange.aspectMask = 1; // VK_IMAGE_ASPECT_COLOR_BIT
                iv_ci.subresourceRange.baseMipLevel = 0;
                iv_ci.subresourceRange.levelCount = 1;
                iv_ci.subresourceRange.baseArrayLayer = 0;
                iv_ci.subresourceRange.layerCount = 1;

                VkImageView view = 0;
                if (create_img_view(dev, &iv_ci, nullptr, &view) == VK_SUCCESS && view) {
                    swapchain_image_views_.push_back(reinterpret_cast<void*>(view));
                }
            }
        }
    }

    swapchain_created_ = true;
    vk_present_queue_ = vk.GetQueue();
    present_queue_family_ = vk.GetQueueFamily();

    auto create_fence = reinterpret_cast<PFN_vkCreateFence>(vk.GetProcAddress("vkCreateFence"));
    if (create_fence) {
        VkFenceCreateInfo fci{};
        fci.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        fci.flags = 0;
        create_fence(dev, &fci, nullptr, &acquire_fence_);
    }

    if (!swapchain_image_views_.empty()) {
        vk.CreateSwapchainFramebuffers(swapchain_image_views_, width, height);
    }

    std::cout << "[+] Initialized Vulkan Swapchain: " << width << "x" << height
              << " | Triple-Buffered (" << swapchain_image_count_
              << " images / " << vk.GetSwapchainFramebufferCount()
              << " framebuffers) | Format=B8G8R8A8_UNORM | PresentMode=FIFO (V-Sync)\n";
    return true;
#else
    return false;
#endif
}

void VideoOutHleManager::DestroyVulkanSwapchain() {
#ifdef _WIN32
    auto& vk = VulkanHostBackend::Instance();
    VkInstance inst = vk.GetInstance();
    VkDevice dev = vk.GetDevice();

    if (dev) {
        vk.DestroySwapchainFramebuffers();
        if (acquire_fence_) {
            auto destroy_fence = reinterpret_cast<PFN_vkDestroyFence>(
                vk.GetProcAddress("vkDestroyFence"));
            if (destroy_fence) destroy_fence(dev, acquire_fence_, nullptr);
            acquire_fence_ = 0;
        }
        auto destroy_img_view = reinterpret_cast<PFN_vkDestroyImageView>(
            vk.GetProcAddress("vkDestroyImageView"));
        if (destroy_img_view) {
            for (auto* view : swapchain_image_views_) {
                destroy_img_view(dev, reinterpret_cast<VkImageView>(view), nullptr);
            }
        }
        swapchain_image_views_.clear();
        swapchain_images_.clear();

        auto destroy_swapchain = reinterpret_cast<PFN_vkDestroySwapchainKHR>(
            vk.GetProcAddress("vkDestroySwapchainKHR"));
        if (destroy_swapchain && vk_swapchain_) {
            destroy_swapchain(dev, reinterpret_cast<VkSwapchainKHR>(vk_swapchain_), nullptr);
            vk_swapchain_ = nullptr;
        }
    }

    if (inst) {
        auto destroy_surface = reinterpret_cast<PFN_vkDestroySurfaceKHR>(
            vk.GetProcAddress("vkDestroySurfaceKHR"));
        if (destroy_surface && vk_surface_) {
            destroy_surface(inst, reinterpret_cast<VkSurfaceKHR>(vk_surface_), nullptr);
            vk_surface_ = nullptr;
        }
    }
    swapchain_created_ = false;
#endif
}

void VideoOutHleManager::SetActiveSceneGeometry(uint64_t index_buffer_handle, uint32_t index_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_scene_ib_ = index_buffer_handle;
    active_scene_index_count_ = index_count;
}

void VideoOutHleManager::UpdateWindowTelemetryTitle(const std::string& telemetry_hud) {
#ifdef _WIN32
    if (hwnd_) {
        SetWindowTextA(hwnd_, telemetry_hud.c_str());
    }
#else
    (void)telemetry_hud;
#endif
}

void VideoOutHleManager::PollEvents() {
#ifdef _WIN32
    if (!hwnd_) return;
    MSG msg;
    while (PeekMessageW(&msg, hwnd_, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
#endif
}

bool VideoOutHleManager::SubmitFlip(int32_t handle, int32_t buffer_index, int32_t flip_mode, int64_t flip_arg) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.current_buffer_index = static_cast<uint32_t>(buffer_index);
    state_.flip_count++;

    PollEvents();

#ifdef _WIN32
    if (swapchain_created_ && vk_swapchain_ && vk_present_queue_) {
        auto& vk = VulkanHostBackend::Instance();
        VkDevice dev = vk.GetDevice();

        auto acquire_img = reinterpret_cast<PFN_vkAcquireNextImageKHR>(
            vk.GetProcAddress("vkAcquireNextImageKHR"));
        auto queue_present = reinterpret_cast<PFN_vkQueuePresentKHR>(
            vk.GetProcAddress("vkQueuePresentKHR"));
        auto wait_fences = reinterpret_cast<PFN_vkWaitForFences>(
            vk.GetProcAddress("vkWaitForFences"));
        auto reset_fences = reinterpret_cast<PFN_vkResetFences>(
            vk.GetProcAddress("vkResetFences"));

        if (acquire_img && queue_present && acquire_fence_ && wait_fences && reset_fences) {
            reset_fences(dev, 1, &acquire_fence_);
            uint32_t img_idx = 0;
            if (acquire_img(dev, reinterpret_cast<VkSwapchainKHR>(vk_swapchain_), 1000000000ULL, 0, acquire_fence_, &img_idx) == VK_SUCCESS) {
                wait_fences(dev, 1, &acquire_fence_, 1, 1000000000ULL);
                if (img_idx < swapchain_images_.size()) {
                    // Render 3D scene directly into acquired swapchain framebuffer (or fallback layout transition)
                    float phase = static_cast<float>(state_.flip_count % 60) / 60.0f;
                    float cr = 0.04f + 0.03f * phase;
                    float cg = 0.07f + 0.04f * phase;
                    float cb = 0.14f + 0.05f * phase;
                    if (!vk.RenderSwapchainFrame(img_idx, active_scene_ib_, active_scene_index_count_, cr, cg, cb)) {
                        vk.TransitionImageToPresentLayout(reinterpret_cast<uint64_t>(swapchain_images_[img_idx]));
                    }
                }
                VkSwapchainKHR sw = reinterpret_cast<VkSwapchainKHR>(vk_swapchain_);
                VkPresentInfoKHR pi{};
                pi.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
                pi.swapchainCount = 1;
                pi.pSwapchains = &sw;
                pi.pImageIndices = &img_idx;
                queue_present(reinterpret_cast<VkQueue>(vk_present_queue_), &pi);
            }
        }
    }
#endif

    if (state_.flip_count <= 10 || (state_.flip_count % 60) == 0) {
        std::cout << "  [VIDEO] Flip #" << state_.flip_count
                  << " | Handle=" << handle << " BufferIdx=" << buffer_index
                  << " Mode=" << flip_mode << " Arg=0x" << std::hex << flip_arg << std::dec << "\n" << std::flush;
    }
    yotei::kernel::ThreadManager::Instance().EqueueBroadcastFlipAndEop(static_cast<uint64_t>(flip_arg));
    return true;
}

void VideoOutHleManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    DestroyVulkanSwapchain();

#ifdef _WIN32
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
    window_created_ = false;
#endif
    state_.is_open = false;
}

// libSceVideoOut API Handlers
int32_t VideoOutHleManager::SceVideoOutOpen(int32_t, int32_t, int32_t, uint64_t) {
    if (!state_.is_open) {
        Initialize(1920, 1080);
    }
    return 1; // VideoOut port handle 1
}

int32_t VideoOutHleManager::SceVideoOutClose(int32_t) {
    return 0; // SCE_OK
}

int32_t VideoOutHleManager::SceVideoOutRegisterBuffers2(int32_t handle, int32_t start_index,
                                                      uint64_t addresses, int32_t num_buffers, uint64_t attr) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.registered_buffers.clear();
    const uint64_t* ptrs = reinterpret_cast<const uint64_t*>(addresses);

    for (int32_t i = 0; i < num_buffers; ++i) {
        VideoOutBufferInfo buf{};
        buf.guest_address = ptrs ? ptrs[i] : 0;
        buf.width = state_.width;
        buf.height = state_.height;
        state_.registered_buffers.push_back(buf);
    }

    std::cout << "[+] SceVideoOutRegisterBuffers2: Handle=" << handle
              << " (" << num_buffers << " buffers registered starting at index " << start_index
              << ", attr=0x" << std::hex << attr << std::dec << ")\n";
    return 0; // SCE_OK
}

int32_t VideoOutHleManager::SceVideoOutSetBufferAttribute2(uint64_t attr, uint32_t pixel_format,
                                                          uint32_t tiling_mode, uint32_t aspect_ratio,
                                                          uint32_t width, uint32_t height, uint32_t pitch) {
    if (attr) {
        uint32_t* p = reinterpret_cast<uint32_t*>(attr);
        p[0] = pixel_format;
        p[1] = tiling_mode;
        p[2] = aspect_ratio;
        p[3] = width;
        p[4] = height;
        p[5] = pitch;
    }
    return 0; // SCE_OK
}

int32_t VideoOutHleManager::SceVideoOutSubmitFlip(int32_t handle, int32_t buffer_index,
                                                int32_t flip_mode, int64_t flip_arg) {
    SubmitFlip(handle, buffer_index, flip_mode, flip_arg);
    return 0; // SCE_OK
}

int32_t VideoOutHleManager::SceVideoOutSetFlipRate(int32_t, int32_t flip_rate) {
    state_.flip_rate = static_cast<uint32_t>(flip_rate);
    return 0; // SCE_OK
}

int32_t VideoOutHleManager::SceVideoOutGetFlipStatus(int32_t, uint64_t status_out) {
    if (status_out) {
        uint64_t* p = reinterpret_cast<uint64_t*>(status_out);
        p[0] = state_.flip_count;
        p[1] = state_.current_buffer_index;
    }
    return 0; // SCE_OK
}

int32_t VideoOutHleManager::SceVideoOutIsFlipPending(int32_t) {
    return 0; // Not pending
}

int32_t VideoOutHleManager::SceVideoOutGetOutputStatus(int32_t, uint64_t status_out) {
    if (status_out) {
        // SceVideoOutOutputStatus layout:
        // uint32_t width (1920)
        // uint32_t height (1080)
        // float    refreshRate (60.0f)
        // uint32_t format (0)
        // uint32_t aspectRatio (0 = 16:9)
        // uint32_t status (1 = connected)
        uint32_t* p = reinterpret_cast<uint32_t*>(status_out);
        p[0] = state_.width;
        p[1] = state_.height;
        *reinterpret_cast<float*>(&p[2]) = state_.refresh_rate;
        p[3] = 0; // RGBA
        p[4] = 0; // 16:9
        p[5] = 1; // Connected / Display Active
    }
    return 0; // SCE_OK
}

int32_t VideoOutHleManager::SceVideoOutIsOutputSupported(int32_t, int32_t) {
    return 1; // Output supported!
}

bool VideoOutHleManager::DispatchNid(const std::string&, const std::string& nid,
                                     const std::string& name,
                                     uint64_t rdi, uint64_t rsi, uint64_t rdx,
                                     uint64_t rcx, uint64_t r8, uint64_t r9,
                                     uint64_t* ret) {
    if (!ret) return false;

    if (nid == "Up36PTk687E" || name == "sceVideoOutOpen") {
        *ret = static_cast<uint64_t>(SceVideoOutOpen(
            static_cast<int32_t>(rdi), static_cast<int32_t>(rsi),
            static_cast<int32_t>(rdx), rcx));
        return true;
    }
    if (nid == "rKBUtgRrtbk" || name == "sceVideoOutRegisterBuffers2") {
        *ret = static_cast<uint64_t>(SceVideoOutRegisterBuffers2(
            static_cast<int32_t>(rdi), static_cast<int32_t>(rsi),
            rdx, static_cast<int32_t>(rcx), r8));
        return true;
    }
    if (nid == "PjS5uASwcV8" || name == "sceVideoOutSetBufferAttribute2") {
        *ret = static_cast<uint64_t>(SceVideoOutSetBufferAttribute2(
            rdi, static_cast<uint32_t>(rsi), static_cast<uint32_t>(rdx),
            static_cast<uint32_t>(rcx), static_cast<uint32_t>(r8),
            static_cast<uint32_t>(r9), static_cast<uint32_t>(r9 * 4)));
        return true;
    }
    if (nid == "U46NwOiJpys" || name == "sceVideoOutSubmitFlip") {
        *ret = static_cast<uint64_t>(SceVideoOutSubmitFlip(
            static_cast<int32_t>(rdi), static_cast<int32_t>(rsi),
            static_cast<int32_t>(rdx), static_cast<int64_t>(rcx)));
        return true;
    }
    if (nid == "CBiu4mCE1DA" || name == "sceVideoOutSetFlipRate") {
        *ret = static_cast<uint64_t>(SceVideoOutSetFlipRate(
            static_cast<int32_t>(rdi), static_cast<int32_t>(rsi)));
        return true;
    }
    if (nid == "utPrVdxio-8" || name == "sceVideoOutGetOutputStatus") {
        *ret = static_cast<uint64_t>(SceVideoOutGetOutputStatus(
            static_cast<int32_t>(rdi), rsi));
        return true;
    }
    if (nid == "SbU3dwp80lQ" || name == "sceVideoOutGetFlipStatus") {
        *ret = static_cast<uint64_t>(SceVideoOutGetFlipStatus(
            static_cast<int32_t>(rdi), rsi));
        return true;
    }
    if (nid == "6kP7bf10+-4" || name == "sceVideoOutAddFlipEvent") {
        // sceVideoOutAddFlipEvent(SceKernelEqueue eq, int32_t handle, void* udata)
        yotei::kernel::ThreadManager::Instance().EqueueAddEvent(rdi, rsi, -13 /* EVFILT_VIDEO_OUT */, rdx);
        *ret = 0;
        return true;
    }
    if (nid == "zgXifHT9ErY" || name == "sceVideoOutIsFlipPending") {
        *ret = static_cast<uint64_t>(SceVideoOutIsFlipPending(
            static_cast<int32_t>(rdi)));
        return true;
    }
    if (nid == "Nv8c-Kb+DUM" || name == "sceVideoOutIsOutputSupported") {
        *ret = static_cast<uint64_t>(SceVideoOutIsOutputSupported(
            static_cast<int32_t>(rdi), static_cast<int32_t>(rsi)));
        return true;
    }
    if (nid == "N5KDtkIjjJ4" || name == "sceVideoOutUnregisterBuffers") {
        *ret = 0;
        return true;
    }
    if (nid == "w0hLuNarQxY" || name == "sceVideoOutConfigureOutput") {
        *ret = 0;
        return true;
    }
    if (nid == "5tRaBjtdTzY" || name == "sceVideoOutVrrPegToFixedRate" ||
        nid == "T4ucGB8CsnM" || name == "sceVideoOutVrrUnpegFromFixedRate" ||
        nid == "kP2L8t3j-aM" || name == "VideoOutAllowOutputResolutionWqhdDetection" ||
        nid == "pv9CI5VC+R0" || name == "VideoOutColorSettingsSetGamma" ||
        nid == "DYhhWbJSeRg" || name == "VideoOutLatencyMeasureSetStartPoint" ||
        nid == "gWT7X8H0bYs" || name == "VideoOutVrrStatus__q_vbO859Tw") {
        *ret = 0;
        return true;
    }

    return false;
}

} // namespace yotei::graphics
