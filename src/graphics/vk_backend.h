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
    uint64_t bda_buffers_allocated = 0;
    uint64_t compute_dispatches_executed = 0;
    uint64_t draw_calls_executed = 0;
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
    bool ExecuteGraphicsDraw(
        uint32_t vertex_count,
        uint32_t instance_count = 1,
        uint32_t first_vertex = 0,
        uint32_t first_instance = 0);

    void Shutdown();

    bool IsInitialized() const { return initialized_; }
    bool IsBdaSupported() const { return gpu_info_.bda_supported; }
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
    uint64_t default_framebuffer_ = 0;
    uint64_t default_color_image_ = 0;
    uint64_t default_color_mem_ = 0;
    uint64_t default_color_view_ = 0;
};

} // namespace yotei::graphics
