#include "graphics/vk_backend.h"
#include <cstring>
#include <iostream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define VKAPI_PTR __stdcall
#else
#define VKAPI_PTR
#endif

namespace yotei::graphics {

namespace {

// Minimal Vulkan 1.3 C ABI structures for zero-dependency dynamic loading via vulkan-1.dll
using VkResult = int32_t;
using VkFlags = uint32_t;
using VkDeviceSize = uint64_t;
using VkInstance = void*;
using VkPhysicalDevice = void*;
using VkDevice = void*;
using VkShaderModule = uint64_t;

constexpr VkResult VK_SUCCESS = 0;
constexpr uint32_t VK_STRUCTURE_TYPE_APPLICATION_INFO = 0;
constexpr uint32_t VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1;
constexpr uint32_t VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 2;
constexpr uint32_t VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 3;
constexpr uint32_t VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO = 16;

constexpr uint32_t MakeVkApiVersion(uint32_t variant, uint32_t major, uint32_t minor, uint32_t patch) {
    return (variant << 29) | (major << 22) | (minor << 12) | patch;
}

struct VkApplicationInfo {
    uint32_t    sType;
    const void* pNext;
    const char* pApplicationName;
    uint32_t    applicationVersion;
    const char* pEngineName;
    uint32_t    engineVersion;
    uint32_t    apiVersion;
};

struct VkInstanceCreateInfo {
    uint32_t                 sType;
    const void*              pNext;
    VkFlags                  flags;
    const VkApplicationInfo* pApplicationInfo;
    uint32_t                 enabledLayerCount;
    const char* const*       ppEnabledLayerNames;
    uint32_t                 enabledExtensionCount;
    const char* const*       ppEnabledExtensionNames;
};

struct VkPhysicalDeviceLimits {
    uint8_t raw_bytes[504];
};

struct VkPhysicalDeviceSparseProperties {
    uint32_t residencyStandard2DBlockShape;
    uint32_t residencyStandard2DMultisampleBlockShape;
    uint32_t residencyStandard3DBlockShape;
    uint32_t residencyAlignedMipSize;
    uint32_t residencyNonResidentStrict;
};

struct VkPhysicalDeviceProperties {
    uint32_t apiVersion;
    uint32_t driverVersion;
    uint32_t vendorID;
    uint32_t deviceID;
    uint32_t deviceType;
    char     deviceName[256];
    uint8_t  pipelineCacheUUID[16];
    uint8_t  limits_and_sparse_padding[1024];
};

struct VkMemoryType {
    uint32_t propertyFlags;
    uint32_t heapIndex;
};

struct VkMemoryHeap {
    VkDeviceSize size;
    uint32_t     flags;
};

struct VkPhysicalDeviceMemoryProperties {
    uint32_t     memoryTypeCount;
    VkMemoryType memoryTypes[32];
    uint32_t     memoryHeapCount;
    VkMemoryHeap memoryHeaps[16];
};

struct VkDeviceQueueCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    queueFamilyIndex;
    uint32_t    queueCount;
    const float* pQueuePriorities;
};

struct VkDeviceCreateInfo {
    uint32_t                       sType;
    const void*                    pNext;
    VkFlags                        flags;
    uint32_t                       queueCreateInfoCount;
    const VkDeviceQueueCreateInfo* pQueueCreateInfos;
    uint32_t                       enabledLayerCount;
    const char* const*             ppEnabledLayerNames;
    uint32_t                       enabledExtensionCount;
    const char* const*             ppEnabledExtensionNames;
    const void*                    pEnabledFeatures;
};

struct VkShaderModuleCreateInfo {
    uint32_t        sType;
    const void*     pNext;
    VkFlags         flags;
    size_t          codeSize;
    const uint32_t* pCode;
};

using PFN_vkGetInstanceProcAddr = void* (VKAPI_PTR*)(VkInstance, const char*);
using PFN_vkCreateInstance = VkResult (VKAPI_PTR*)(const VkInstanceCreateInfo*, const void*, VkInstance*);
using PFN_vkDestroyInstance = void (VKAPI_PTR*)(VkInstance, const void*);
using PFN_vkEnumeratePhysicalDevices = VkResult (VKAPI_PTR*)(VkInstance, uint32_t*, VkPhysicalDevice*);
using PFN_vkGetPhysicalDeviceProperties = void (VKAPI_PTR*)(VkPhysicalDevice, VkPhysicalDeviceProperties*);
using PFN_vkGetPhysicalDeviceMemoryProperties = void (VKAPI_PTR*)(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties*);
using PFN_vkCreateDevice = VkResult (VKAPI_PTR*)(VkPhysicalDevice, const VkDeviceCreateInfo*, const void*, VkDevice*);
using PFN_vkDestroyDevice = void (VKAPI_PTR*)(VkDevice, const void*);
using PFN_vkCreateShaderModule = VkResult (VKAPI_PTR*)(VkDevice, const VkShaderModuleCreateInfo*, const void*, VkShaderModule*);
using PFN_vkDestroyShaderModule = void (VKAPI_PTR*)(VkDevice, VkShaderModule, const void*);

} // namespace

VulkanHostBackend& VulkanHostBackend::Instance() {
    static VulkanHostBackend instance;
    return instance;
}

bool VulkanHostBackend::Initialize() {
    if (initialized_) return true;

#ifdef _WIN32
    HMODULE dll = LoadLibraryA("vulkan-1.dll");
    if (!dll) return false;
    vulkan_dll_ = dll;

    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(dll, "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_inst = reinterpret_cast<PFN_vkCreateInstance>(
        get_proc(nullptr, "vkCreateInstance"));
    if (!create_inst) return false;

    VkApplicationInfo app_info{};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "Ghost of Yotei (YoteiPort HLE)";
    app_info.applicationVersion = MakeVkApiVersion(0, 0, 1, 0);
    app_info.pEngineName = "SuckerPunch/YoteiPort AGC-to-Vulkan";
    app_info.engineVersion = MakeVkApiVersion(0, 0, 1, 0);
    app_info.apiVersion = MakeVkApiVersion(0, 1, 3, 0);

    const char* const inst_extensions[] = {
        "VK_KHR_surface",
        "VK_KHR_win32_surface",
    };

    VkInstanceCreateInfo inst_ci{};
    inst_ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    inst_ci.pApplicationInfo = &app_info;
    inst_ci.enabledExtensionCount = 2;
    inst_ci.ppEnabledExtensionNames = inst_extensions;

    VkInstance inst = nullptr;
    if (create_inst(&inst_ci, nullptr, &inst) != VK_SUCCESS || !inst) {
        // Fallback without extensions if surface extension is missing
        inst_ci.enabledExtensionCount = 0;
        inst_ci.ppEnabledExtensionNames = nullptr;
        if (create_inst(&inst_ci, nullptr, &inst) != VK_SUCCESS || !inst) {
            return false;
        }
    }
    vk_instance_ = inst;

    auto enum_devs = reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(
        get_proc(inst, "vkEnumeratePhysicalDevices"));
    auto get_props = reinterpret_cast<PFN_vkGetPhysicalDeviceProperties>(
        get_proc(inst, "vkGetPhysicalDeviceProperties"));
    auto get_mem_props = reinterpret_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(
        get_proc(inst, "vkGetPhysicalDeviceMemoryProperties"));
    auto create_dev = reinterpret_cast<PFN_vkCreateDevice>(
        get_proc(inst, "vkCreateDevice"));

    if (!enum_devs || !get_props || !get_mem_props || !create_dev) return false;

    uint32_t dev_count = 0;
    if (enum_devs(inst, &dev_count, nullptr) != VK_SUCCESS || dev_count == 0) {
        return false;
    }
    std::vector<VkPhysicalDevice> phys_devs(dev_count);
    enum_devs(inst, &dev_count, phys_devs.data());

    // Pick first discrete GPU (deviceType == 2) or fallback to [0]
    VkPhysicalDevice chosen = phys_devs[0];
    VkPhysicalDeviceProperties chosen_props{};
    get_props(chosen, &chosen_props);
    for (uint32_t i = 0; i < dev_count; ++i) {
        VkPhysicalDeviceProperties p{};
        get_props(phys_devs[i], &p);
        if (p.deviceType == 2) { // VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU
            chosen = phys_devs[i];
            chosen_props = p;
            break;
        }
    }
    vk_phys_device_ = chosen;

    gpu_info_.device_name = chosen_props.deviceName;
    gpu_info_.vendor_id = chosen_props.vendorID;
    gpu_info_.device_id = chosen_props.deviceID;
    gpu_info_.api_version_major = (chosen_props.apiVersion >> 22) & 0x7FU;
    gpu_info_.api_version_minor = (chosen_props.apiVersion >> 12) & 0x3FFU;
    gpu_info_.api_version_patch = chosen_props.apiVersion & 0xFFFU;

    VkPhysicalDeviceMemoryProperties mem_props{};
    get_mem_props(chosen, &mem_props);
    uint64_t total_device_local = 0;
    for (uint32_t h = 0; h < mem_props.memoryHeapCount; ++h) {
        if (mem_props.memoryHeaps[h].flags & 0x1U) { // VK_MEMORY_HEAP_DEVICE_LOCAL_BIT
            total_device_local += mem_props.memoryHeaps[h].size;
        }
    }
    gpu_info_.vram_bytes = total_device_local;

    float queue_prio = 1.0f;
    VkDeviceQueueCreateInfo qci{};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = 0;
    qci.queueCount = 1;
    qci.pQueuePriorities = &queue_prio;

    const char* const dev_extensions[] = {
        "VK_KHR_swapchain",
    };

    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    dci.enabledExtensionCount = 1;
    dci.ppEnabledExtensionNames = dev_extensions;

    VkDevice dev = nullptr;
    if (create_dev(chosen, &dci, nullptr, &dev) != VK_SUCCESS || !dev) {
        // Fallback without extension
        dci.enabledExtensionCount = 0;
        dci.ppEnabledExtensionNames = nullptr;
        create_dev(chosen, &dci, nullptr, &dev);
    }

    if (dev) {
        vk_device_ = dev;
        gpu_info_.device_created = true;

        using PFN_vkGetDeviceQueue = void (VKAPI_PTR*)(VkDevice, uint32_t, uint32_t, void**);
        auto get_queue = reinterpret_cast<PFN_vkGetDeviceQueue>(get_proc(inst, "vkGetDeviceQueue"));
        if (get_queue) {
            get_queue(dev, 0, 0, &vk_queue_);
        }
    }

    initialized_ = true;
    return true;
#else
    return false;
#endif
}

void* VulkanHostBackend::GetProcAddress(const char* name) {
#ifdef _WIN32
    if (!vulkan_dll_) return nullptr;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return nullptr;
    return get_proc(vk_instance_, name);
#else
    return nullptr;
#endif
}

bool VulkanHostBackend::VerifySpirvShaderModule(const std::vector<uint32_t>& spirv_words) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vulkan_dll_ || spirv_words.empty()) return false;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_sm = reinterpret_cast<PFN_vkCreateShaderModule>(
        get_proc(vk_instance_, "vkCreateShaderModule"));
    auto destroy_sm = reinterpret_cast<PFN_vkDestroyShaderModule>(
        get_proc(vk_instance_, "vkDestroyShaderModule"));
    if (!create_sm || !destroy_sm) return false;

    VkShaderModuleCreateInfo sm_ci{};
    sm_ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm_ci.codeSize = spirv_words.size() * sizeof(uint32_t);
    sm_ci.pCode = spirv_words.data();

    VkShaderModule mod = 0;
    if (create_sm(vk_device_, &sm_ci, nullptr, &mod) == VK_SUCCESS && mod != 0) {
        destroy_sm(vk_device_, mod, nullptr);
        gpu_info_.spirv_module_verified = true;
        return true;
    }
#endif
    return false;
}

void VulkanHostBackend::Shutdown() {
#ifdef _WIN32
    if (!initialized_ || !vulkan_dll_) return;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (get_proc) {
        if (vk_device_) {
            auto destroy_dev = reinterpret_cast<PFN_vkDestroyDevice>(
                get_proc(vk_instance_, "vkDestroyDevice"));
            if (destroy_dev) destroy_dev(vk_device_, nullptr);
            vk_device_ = nullptr;
        }
        if (vk_instance_) {
            auto destroy_inst = reinterpret_cast<PFN_vkDestroyInstance>(
                get_proc(vk_instance_, "vkDestroyInstance"));
            if (destroy_inst) destroy_inst(vk_instance_, nullptr);
            vk_instance_ = nullptr;
        }
    }
    FreeLibrary(static_cast<HMODULE>(vulkan_dll_));
    vulkan_dll_ = nullptr;
    initialized_ = false;
#endif
}

} // namespace yotei::graphics
