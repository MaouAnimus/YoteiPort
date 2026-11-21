#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace yotei::graphics {

struct VulkanGpuInfo {
    std::string device_name;
    uint32_t vendor_id = 0;
    uint32_t device_id = 0;
    uint32_t api_version_major = 0;
    uint32_t api_version_minor = 0;
    uint32_t api_version_patch = 0;
    uint64_t vram_bytes = 0;
    bool     device_created = false;
    bool     spirv_module_verified = false;
    bool     bda_supported = false;
    bool     bindless_supported = false;
    uint32_t bindless_textures_registered = 0;
    uint32_t bindless_samplers_registered = 0;
    uint64_t bda_buffers_allocated = 0;
    uint64_t compute_dispatches_executed = 0;
    uint64_t draw_calls_executed = 0;
    uint64_t swapchain_frames_rendered = 0;
};

struct GpuBufferAllocation {
    uint64_t buffer_handle = 0;   // VkBuffer
    uint64_t memory_handle = 0;   // VkDeviceMemory
    uint64_t device_address = 0;  // 64-bit GPU virtual address (BDA)
    uint64_t size = 0;
    void*    host_mapped_ptr = nullptr;
};

class VulkanHostBackend {
public:
    static VulkanHostBackend& Instance();

    bool Initialize();
    bool VerifySpirvShaderModule(const std::vector<uint32_t>& spirv_words);
    bool ExecuteCompute(
        const std::vector<uint32_t>& spirv_words,
        uint32_t groups_x = 1,
        uint32_t groups_y = 1,
        uint32_t groups_z = 1);
    bool ExecuteDraw(
        uint32_t vertex_count,
        uint32_t instance_count = 1,
        uint32_t first_vertex = 0,
        uint32_t first_instance = 0);
    bool ExecuteDrawIndexed(
        uint32_t index_count,
        uint32_t instance_count = 1,
        uint32_t first_index = 0,
        int32_t vertex_offset = 0,
        uint32_t first_instance = 0);

    // Buffer Device Address (BDA) 64-bit Memory API
    GpuBufferAllocation AllocateBufferWithDeviceAddress(
        uint64_t size,
        uint32_t usage_flags,
        bool host_visible = true);
    void FreeBufferWithDeviceAddress(const GpuBufferAllocation& alloc);
    uint64_t GetBufferDeviceAddress(uint64_t buffer_handle) const;

    // Graphics Pipeline API
    bool CreateDefaultGraphicsPipeline();
    bool CreateMultiStageGraphicsPipeline(
        const std::vector<uint32_t>& vs_spirv,
        const std::vector<uint32_t>& fs_spirv);
    bool ExecuteGraphicsDraw(
        uint32_t vertex_count,
        uint32_t instance_count = 1,
        uint32_t first_vertex = 0,
        uint32_t first_instance = 0);
    bool ExecuteMultiStageDrawIndexed(
        uint32_t index_count,
        uint32_t instance_count = 1,
        uint32_t first_index = 0,
        int32_t vertex_offset = 0,
        uint32_t first_instance = 0);

    // Hi-Z Occlusion Culling & Depth Readback API
    uint64_t CreateDepthTargetImage(
        uint32_t width,
        uint32_t height,
        uint32_t vk_format,
        uint64_t* out_view);
    bool TransferImageToLinearBuffer(
        uint64_t src_image,
        uint64_t dst_buffer,
        uint32_t width,
        uint32_t height);
    bool TransitionImageToPresentLayout(uint64_t image);

    // Swapchain Framebuffer 3D Rendering API (Milestone 16)
    bool CreateSwapchainFramebuffers(
        const std::vector<void*>& image_views,
        uint32_t width,
        uint32_t height);
    void DestroySwapchainFramebuffers();
    bool RenderSwapchainFrame(
        uint32_t image_index,
        uint64_t index_buffer,
        uint32_t index_count,
        float clear_r = 0.05f,
        float clear_g = 0.08f,
        float clear_b = 0.14f);
    size_t GetSwapchainFramebufferCount() const { return swapchain_framebuffers_.size(); }

    void Shutdown();

    // Bindless Descriptor Heap API (Descriptor Set 1)
    bool InitializeBindlessHeap();
    bool RegisterBindlessTexture(uint32_t slot, uint64_t image_view, uint32_t image_layout);
    bool RegisterBindlessSampler(uint32_t slot, uint64_t sampler);
    uint64_t CreateTexture2D(
        uint32_t width,
        uint32_t height,
        uint32_t vk_format,
        const void* initial_data,
        size_t data_size,
        uint64_t* out_view);

    bool IsInitialized() const { return initialized_; }
    bool IsBdaSupported() const { return gpu_info_.bda_supported; }
    bool IsBindlessSupported() const { return gpu_info_.bindless_supported; }
    uint64_t GetBindlessDescriptorSet() const { return bindless_descriptor_set_; }
    uint64_t GetBindlessPipelineLayout() const { return bindless_pipeline_layout_; }
    const VulkanGpuInfo& GetGpuInfo() const { return gpu_info_; }

    void* GetInstance() const { return vk_instance_; }
    void* GetPhysicalDevice() const { return vk_phys_device_; }
    void* GetDevice() const { return vk_device_; }
    void* GetQueue() const { return vk_queue_; }
    uint32_t GetQueueFamily() const { return queue_family_index_; }
    void* GetProcAddress(const char* name);

private:
    VulkanHostBackend() = default;

    bool initialized_ = false;
    void* vulkan_dll_ = nullptr;
    void* vk_instance_ = nullptr;
    void* vk_phys_device_ = nullptr;
    void* vk_device_ = nullptr;
    void* vk_queue_ = nullptr;
    uint32_t queue_family_index_ = 0;
    VulkanGpuInfo gpu_info_{};

    // Graphics Pipeline handles
    uint64_t default_render_pass_ = 0;
    uint64_t default_pipeline_layout_ = 0;
    uint64_t default_graphics_pipeline_ = 0;
    uint64_t multi_stage_pipeline_layout_ = 0;
    uint64_t multi_stage_graphics_pipeline_ = 0;
    uint64_t default_framebuffer_ = 0;
    uint64_t default_color_image_ = 0;
    uint64_t default_color_mem_ = 0;
    uint64_t default_color_view_ = 0;

    // Bindless Descriptor Set 1 handles
    uint64_t bindless_desc_layout_ = 0;
    uint64_t bindless_desc_pool_ = 0;
    uint64_t bindless_descriptor_set_ = 0;
    uint64_t bindless_pipeline_layout_ = 0;

    // Swapchain Framebuffer handles (1920x1080 Triple-Buffered)
    uint64_t swapchain_render_pass_ = 0;
    std::vector<uint64_t> swapchain_framebuffers_;
    uint32_t swapchain_fb_width_ = 1920;
    uint32_t swapchain_fb_height_ = 1080;
};

} // namespace yotei::graphics
