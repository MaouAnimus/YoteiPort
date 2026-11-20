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
    void Shutdown();

    bool IsInitialized() const { return initialized_; }
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
};

} // namespace yotei::graphics
