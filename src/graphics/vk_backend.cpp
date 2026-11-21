#include "graphics/vk_backend.h"
#include "graphics/rdna2_shader.h"
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
using VkQueue = void*;
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

using VkCommandPool = uint64_t;
using VkCommandBuffer = void*;
using VkPipelineLayout = uint64_t;
using VkPipeline = uint64_t;
using VkPipelineCache = uint64_t;
using VkFence = uint64_t;

constexpr uint32_t VK_STRUCTURE_TYPE_SUBMIT_INFO = 4;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO = 18;
constexpr uint32_t VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO = 29;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO = 30;
constexpr uint32_t VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO = 39;
constexpr uint32_t VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO = 40;
constexpr uint32_t VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO = 42;

struct VkPipelineShaderStageCreateInfo {
    uint32_t        sType;
    const void*     pNext;
    VkFlags         flags;
    uint32_t        stage; // 0x00000020 for VK_SHADER_STAGE_COMPUTE_BIT
    VkShaderModule  module;
    const char*     pName;
    const void*     pSpecializationInfo;
};

struct VkComputePipelineCreateInfo {
    uint32_t                        sType;
    const void*                     pNext;
    VkFlags                         flags;
    VkPipelineShaderStageCreateInfo stage;
    VkPipelineLayout                layout;
    VkPipeline                      basePipelineHandle;
    int32_t                         basePipelineIndex;
};

struct VkPipelineLayoutCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    setLayoutCount;
    const void* pSetLayouts;
    uint32_t    pushConstantRangeCount;
    const void* pPushConstantRanges;
};

struct VkCommandPoolCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    queueFamilyIndex;
};

struct VkCommandBufferAllocateInfo {
    uint32_t        sType;
    const void*     pNext;
    VkCommandPool   commandPool;
    uint32_t        level;
    uint32_t        commandBufferCount;
};

struct VkCommandBufferBeginInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    const void* pInheritanceInfo;
};

struct VkSubmitInfo {
    uint32_t                sType;
    const void*             pNext;
    uint32_t                waitSemaphoreCount;
    const void*             pWaitSemaphores;
    const VkFlags*          pWaitDstStageMask;
    uint32_t                commandBufferCount;
    const VkCommandBuffer*  pCommandBuffers;
    uint32_t                signalSemaphoreCount;
    const void*             pSignalSemaphores;
};

using PFN_vkCreatePipelineLayout = VkResult (VKAPI_PTR*)(VkDevice, const VkPipelineLayoutCreateInfo*, const void*, VkPipelineLayout*);
using PFN_vkDestroyPipelineLayout = void (VKAPI_PTR*)(VkDevice, VkPipelineLayout, const void*);
using PFN_vkCreateComputePipelines = VkResult (VKAPI_PTR*)(VkDevice, VkPipelineCache, uint32_t, const VkComputePipelineCreateInfo*, const void*, VkPipeline*);
using PFN_vkDestroyPipeline = void (VKAPI_PTR*)(VkDevice, VkPipeline, const void*);
using PFN_vkCreateCommandPool = VkResult (VKAPI_PTR*)(VkDevice, const VkCommandPoolCreateInfo*, const void*, VkCommandPool*);
using PFN_vkDestroyCommandPool = void (VKAPI_PTR*)(VkDevice, VkCommandPool, const void*);
using PFN_vkAllocateCommandBuffers = VkResult (VKAPI_PTR*)(VkDevice, const VkCommandBufferAllocateInfo*, VkCommandBuffer*);
using PFN_vkFreeCommandBuffers = void (VKAPI_PTR*)(VkDevice, VkCommandPool, uint32_t, const VkCommandBuffer*);
using PFN_vkBeginCommandBuffer = VkResult (VKAPI_PTR*)(VkCommandBuffer, const VkCommandBufferBeginInfo*);
using PFN_vkEndCommandBuffer = VkResult (VKAPI_PTR*)(VkCommandBuffer);
using PFN_vkCmdBindPipeline = void (VKAPI_PTR*)(VkCommandBuffer, uint32_t, VkPipeline);
using PFN_vkCmdDispatch = void (VKAPI_PTR*)(VkCommandBuffer, uint32_t, uint32_t, uint32_t);
using PFN_vkCmdDraw = void (VKAPI_PTR*)(VkCommandBuffer, uint32_t, uint32_t, uint32_t, uint32_t);
using PFN_vkCmdDrawIndexed = void (VKAPI_PTR*)(VkCommandBuffer, uint32_t, uint32_t, uint32_t, int32_t, uint32_t);
using PFN_vkQueueSubmit = VkResult (VKAPI_PTR*)(VkQueue, uint32_t, const VkSubmitInfo*, VkFence);
using PFN_vkQueueWaitIdle = VkResult (VKAPI_PTR*)(VkQueue);

// BDA & Buffer/Memory constants and structures
constexpr uint32_t VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO = 5;
constexpr uint32_t VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO = 12;
constexpr uint32_t VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO = 1000060000;
constexpr uint32_t VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO = 1000244001;
constexpr uint32_t VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES = 1000257000;
constexpr uint32_t VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_INDEXING_FEATURES = 1000161000;
constexpr uint32_t VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO = 1000161002;
constexpr uint32_t VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET = 35;
constexpr uint32_t VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO = 14;
constexpr uint32_t VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO = 15;
constexpr uint32_t VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER = 45;

constexpr uint32_t VK_DESCRIPTOR_BINDING_UPDATE_AFTER_BIND_BIT = 0x00000001;
constexpr uint32_t VK_DESCRIPTOR_BINDING_PARTIALLY_BOUND_BIT = 0x00000004;
constexpr uint32_t VK_DESCRIPTOR_POOL_CREATE_UPDATE_AFTER_BIND_BIT = 0x00000002;

struct VkPhysicalDeviceDescriptorIndexingFeatures {
    uint32_t sType;
    void*    pNext;
    uint32_t shaderInputAttachmentArrayDynamicIndexing;
    uint32_t shaderUniformTexelBufferArrayDynamicIndexing;
    uint32_t shaderStorageTexelBufferArrayDynamicIndexing;
    uint32_t shaderUniformBufferArrayNonUniformIndexing;
    uint32_t shaderSampledImageArrayNonUniformIndexing;
    uint32_t shaderStorageBufferArrayNonUniformIndexing;
    uint32_t shaderStorageImageArrayNonUniformIndexing;
    uint32_t shaderInputAttachmentArrayNonUniformIndexing;
    uint32_t shaderUniformTexelBufferArrayNonUniformIndexing;
    uint32_t shaderStorageTexelBufferArrayNonUniformIndexing;
    uint32_t descriptorBindingUniformBufferUpdateAfterBind;
    uint32_t descriptorBindingSampledImageUpdateAfterBind;
    uint32_t descriptorBindingStorageImageUpdateAfterBind;
    uint32_t descriptorBindingStorageBufferUpdateAfterBind;
    uint32_t descriptorBindingUniformTexelBufferUpdateAfterBind;
    uint32_t descriptorBindingStorageTexelBufferUpdateAfterBind;
    uint32_t descriptorBindingUpdateUnusedWhilePending;
    uint32_t descriptorBindingPartiallyBound;
    uint32_t descriptorBindingVariableDescriptorCount;
    uint32_t runtimeDescriptorArray;
};

struct VkDescriptorSetLayoutBindingFlagsCreateInfo {
    uint32_t        sType;
    const void*     pNext;
    uint32_t        bindingCount;
    const uint32_t* pBindingFlags;
};

struct VkDescriptorImageInfo {
    uint64_t sampler;
    uint64_t imageView;
    uint32_t imageLayout;
};

struct VkWriteDescriptorSet {
    uint32_t       sType;
    const void*    pNext;
    uint64_t       dstSet;
    uint32_t       dstBinding;
    uint32_t       dstArrayElement;
    uint32_t       descriptorCount;
    uint32_t       descriptorType;
    const VkDescriptorImageInfo* pImageInfo;
    const void*    pBufferInfo;
    const void*    pTexelBufferView;
};

constexpr uint32_t VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO = 32;
constexpr uint32_t VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO = 33;
constexpr uint32_t VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO = 34;

struct VkDescriptorSetLayoutBinding {
    uint32_t binding;
    uint32_t descriptorType;
    uint32_t descriptorCount;
    VkFlags  stageFlags;
    const void* pImmutableSamplers;
};

struct VkDescriptorSetLayoutCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags  flags;
    uint32_t bindingCount;
    const VkDescriptorSetLayoutBinding* pBindings;
};

struct VkDescriptorPoolSize {
    uint32_t type;
    uint32_t descriptorCount;
};

struct VkDescriptorPoolCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags  flags;
    uint32_t maxSets;
    uint32_t poolSizeCount;
    const VkDescriptorPoolSize* pPoolSizes;
};

struct VkDescriptorSetAllocateInfo {
    uint32_t sType;
    const void* pNext;
    uint64_t descriptorPool;
    uint32_t descriptorSetCount;
    const uint64_t* pSetLayouts;
};

constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO = 19;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO = 20;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO = 22;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO = 23;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO = 24;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO = 26;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO = 27;
constexpr uint32_t VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO = 28;
constexpr uint32_t VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO = 38;

struct VkPhysicalDeviceBufferDeviceAddressFeatures {
    uint32_t sType;
    void*    pNext;
    uint32_t bufferDeviceAddress;
    uint32_t bufferDeviceAddressCaptureReplay;
    uint32_t bufferDeviceAddressMultiDevice;
};

struct VkBufferCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    VkDeviceSize size;
    VkFlags     usage;
    uint32_t    sharingMode;
    uint32_t    queueFamilyIndexCount;
    const uint32_t* pQueueFamilyIndices;
};

struct VkMemoryRequirements {
    VkDeviceSize size;
    VkDeviceSize alignment;
    uint32_t     memoryTypeBits;
};

struct VkMemoryAllocateFlagsInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    deviceMask;
};

struct VkMemoryAllocateInfo {
    uint32_t    sType;
    const void* pNext;
    VkDeviceSize allocationSize;
    uint32_t    memoryTypeIndex;
};

struct VkBufferDeviceAddressInfo {
    uint32_t    sType;
    const void* pNext;
    uint64_t    buffer;
};

struct VkViewport {
    float x;
    float y;
    float width;
    float height;
    float minDepth;
    float maxDepth;
};

struct VkRect2D {
    struct { int32_t x; int32_t y; } offset;
    struct { uint32_t width; uint32_t height; } extent;
};

struct VkPipelineVertexInputStateCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    vertexBindingDescriptionCount;
    const void* pVertexBindingDescriptions;
    uint32_t    vertexAttributeDescriptionCount;
    const void* pVertexAttributeDescriptions;
};

struct VkPipelineInputAssemblyStateCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    topology;
    uint32_t    primitiveRestartEnable;
};

struct VkPipelineViewportStateCreateInfo {
    uint32_t          sType;
    const void*       pNext;
    VkFlags           flags;
    uint32_t          viewportCount;
    const VkViewport* pViewports;
    uint32_t          scissorCount;
    const VkRect2D*   pScissors;
};

struct VkPipelineRasterizationStateCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    depthClampEnable;
    uint32_t    rasterizerDiscardEnable;
    uint32_t    polygonMode;
    VkFlags     cullMode;
    uint32_t    frontFace;
    uint32_t    depthBiasEnable;
    float       depthBiasConstantFactor;
    float       depthBiasClamp;
    float       depthBiasSlopeFactor;
    float       lineWidth;
};

struct VkPipelineMultisampleStateCreateInfo {
    uint32_t    sType;
    const void* pNext;
    VkFlags     flags;
    uint32_t    rasterizationSamples;
    uint32_t    sampleShadingEnable;
    float       minSampleShading;
    const void* pSampleMask;
    uint32_t    alphaToCoverageEnable;
    uint32_t    alphaToOneEnable;
};

struct VkPipelineColorBlendAttachmentState {
    uint32_t blendEnable;
    uint32_t srcColorBlendFactor;
    uint32_t dstColorBlendFactor;
    uint32_t colorBlendOp;
    uint32_t srcAlphaBlendFactor;
    uint32_t dstAlphaBlendFactor;
    uint32_t alphaBlendOp;
    VkFlags  colorWriteMask;
};

struct VkPipelineColorBlendStateCreateInfo {
    uint32_t                                   sType;
    const void*                                pNext;
    VkFlags                                    flags;
    uint32_t                                   logicOpEnable;
    uint32_t                                   logicOp;
    uint32_t                                   attachmentCount;
    const VkPipelineColorBlendAttachmentState* pAttachments;
    float                                      blendConstants[4];
};

struct VkPipelineDynamicStateCreateInfo {
    uint32_t        sType;
    const void*     pNext;
    VkFlags         flags;
    uint32_t        dynamicStateCount;
    const uint32_t* pDynamicStates;
};

struct VkGraphicsPipelineCreateInfo {
    uint32_t                                      sType;
    const void*                                   pNext;
    VkFlags                                       flags;
    uint32_t                                      stageCount;
    const VkPipelineShaderStageCreateInfo*        pStages;
    const VkPipelineVertexInputStateCreateInfo*   pVertexInputState;
    const VkPipelineInputAssemblyStateCreateInfo* pInputAssemblyState;
    const void*                                   pTessellationState;
    const VkPipelineViewportStateCreateInfo*      pViewportState;
    const VkPipelineRasterizationStateCreateInfo* pRasterizationState;
    const VkPipelineMultisampleStateCreateInfo*   pMultisampleState;
    const void*                                   pDepthStencilState;
    const VkPipelineColorBlendStateCreateInfo*    pColorBlendState;
    const VkPipelineDynamicStateCreateInfo*       pDynamicState;
    VkPipelineLayout                              layout;
    uint64_t                                      renderPass;
    uint32_t                                      subpass;
    VkPipeline                                    basePipelineHandle;
    int32_t                                       basePipelineIndex;
};

struct VkAttachmentDescription {
    VkFlags  flags;
    uint32_t format;
    uint32_t samples;
    uint32_t loadOp;
    uint32_t storeOp;
    uint32_t stencilLoadOp;
    uint32_t stencilStoreOp;
    uint32_t initialLayout;
    uint32_t finalLayout;
};

struct VkAttachmentReference {
    uint32_t attachment;
    uint32_t layout;
};

struct VkSubpassDescription {
    VkFlags                       flags;
    uint32_t                      pipelineBindPoint;
    uint32_t                      inputAttachmentCount;
    const void*                   pInputAttachments;
    uint32_t                      colorAttachmentCount;
    const VkAttachmentReference*  pColorAttachments;
    const void*                   pResolveAttachments;
    const void*                   pDepthStencilAttachment;
    uint32_t                      preserveAttachmentCount;
    const void*                   pPreserveAttachments;
};

struct VkRenderPassCreateInfo {
    uint32_t                       sType;
    const void*                    pNext;
    VkFlags                        flags;
    uint32_t                       attachmentCount;
    const VkAttachmentDescription* pAttachments;
    uint32_t                       subpassCount;
    const VkSubpassDescription*    pSubpasses;
    uint32_t                       dependencyCount;
    const void*                    pDependencies;
};

using PFN_vkCreateBuffer = VkResult (VKAPI_PTR*)(VkDevice, const VkBufferCreateInfo*, const void*, uint64_t*);
using PFN_vkDestroyBuffer = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkGetBufferMemoryRequirements = void (VKAPI_PTR*)(VkDevice, uint64_t, VkMemoryRequirements*);
using PFN_vkAllocateMemory = VkResult (VKAPI_PTR*)(VkDevice, const VkMemoryAllocateInfo*, const void*, uint64_t*);
using PFN_vkFreeMemory = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkBindBufferMemory = VkResult (VKAPI_PTR*)(VkDevice, uint64_t, uint64_t, VkDeviceSize);
using PFN_vkMapMemory = VkResult (VKAPI_PTR*)(VkDevice, uint64_t, VkDeviceSize, VkDeviceSize, VkFlags, void**);
using PFN_vkUnmapMemory = void (VKAPI_PTR*)(VkDevice, uint64_t);
using PFN_vkGetBufferDeviceAddress = uint64_t (VKAPI_PTR*)(VkDevice, const VkBufferDeviceAddressInfo*);
using PFN_vkCreateRenderPass = VkResult (VKAPI_PTR*)(VkDevice, const VkRenderPassCreateInfo*, const void*, uint64_t*);
using PFN_vkDestroyRenderPass = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkCreateGraphicsPipelines = VkResult (VKAPI_PTR*)(VkDevice, VkPipelineCache, uint32_t, const VkGraphicsPipelineCreateInfo*, const void*, VkPipeline*);
using PFN_vkCmdSetViewport = void (VKAPI_PTR*)(VkCommandBuffer, uint32_t, uint32_t, const VkViewport*);
using PFN_vkCmdSetScissor = void (VKAPI_PTR*)(VkCommandBuffer, uint32_t, uint32_t, const VkRect2D*);
using PFN_vkUpdateDescriptorSets = void (VKAPI_PTR*)(VkDevice, uint32_t, const VkWriteDescriptorSet*, uint32_t, const void*);
using PFN_vkCreateImage = VkResult (VKAPI_PTR*)(VkDevice, const void*, const void*, uint64_t*);
using PFN_vkDestroyImage = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkGetImageMemoryRequirements = void (VKAPI_PTR*)(VkDevice, uint64_t, VkMemoryRequirements*);
using PFN_vkBindImageMemory = VkResult (VKAPI_PTR*)(VkDevice, uint64_t, uint64_t, VkDeviceSize);
using PFN_vkCreateImageView = VkResult (VKAPI_PTR*)(VkDevice, const void*, const void*, uint64_t*);
using PFN_vkDestroyImageView = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkCreateDescriptorSetLayout = VkResult (VKAPI_PTR*)(VkDevice, const VkDescriptorSetLayoutCreateInfo*, const void*, uint64_t*);
using PFN_vkDestroyDescriptorSetLayout = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkCreateDescriptorPool = VkResult (VKAPI_PTR*)(VkDevice, const VkDescriptorPoolCreateInfo*, const void*, uint64_t*);
using PFN_vkDestroyDescriptorPool = void (VKAPI_PTR*)(VkDevice, uint64_t, const void*);
using PFN_vkAllocateDescriptorSets = VkResult (VKAPI_PTR*)(VkDevice, const VkDescriptorSetAllocateInfo*, uint64_t*);
using PFN_vkCmdBindDescriptorSets = void (VKAPI_PTR*)(VkCommandBuffer, uint32_t, uint64_t, uint32_t, uint32_t, const uint64_t*, uint32_t, const uint32_t*);

struct VkBufferImageCopy {
    VkDeviceSize bufferOffset;
    uint32_t     bufferRowLength;
    uint32_t     bufferImageHeight;
    struct {
        uint32_t aspectMask;
        uint32_t mipLevel;
        uint32_t baseArrayLayer;
        uint32_t layerCount;
    } imageSubresource;
    struct { int32_t x, y, z; } imageOffset;
    struct { uint32_t width, height, depth; } imageExtent;
};

struct VkImageMemoryBarrier {
    uint32_t    sType;
    const void* pNext;
    VkFlags     srcAccessMask;
    VkFlags     dstAccessMask;
    uint32_t    oldLayout;
    uint32_t    newLayout;
    uint32_t    srcQueueFamilyIndex;
    uint32_t    dstQueueFamilyIndex;
    uint64_t    image;
    struct {
        uint32_t aspectMask;
        uint32_t baseMipLevel;
        uint32_t levelCount;
        uint32_t baseArrayLayer;
        uint32_t layerCount;
    } subresourceRange;
};

using PFN_vkCmdPipelineBarrier = void (VKAPI_PTR*)(
    VkCommandBuffer, VkFlags, VkFlags, VkFlags,
    uint32_t, const void*,
    uint32_t, const void*,
    uint32_t, const VkImageMemoryBarrier*);

using PFN_vkCmdCopyImageToBuffer = void (VKAPI_PTR*)(
    VkCommandBuffer, uint64_t, uint32_t, uint64_t,
    uint32_t, const VkBufferImageCopy*);

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

    const char* dev_extensions[] = {
        "VK_KHR_swapchain",
        "VK_KHR_buffer_device_address",
    };

    VkPhysicalDeviceDescriptorIndexingFeatures di_features{};
    di_features.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_INDEXING_FEATURES;
    di_features.shaderSampledImageArrayNonUniformIndexing = 1;
    di_features.descriptorBindingSampledImageUpdateAfterBind = 1;
    di_features.descriptorBindingPartiallyBound = 1;
    di_features.descriptorBindingVariableDescriptorCount = 1;
    di_features.runtimeDescriptorArray = 1;

    VkPhysicalDeviceBufferDeviceAddressFeatures bda_features{};
    bda_features.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES;
    bda_features.pNext = &di_features;
    bda_features.bufferDeviceAddress = 1;

    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.pNext = &bda_features;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    dci.enabledExtensionCount = 2;
    dci.ppEnabledExtensionNames = dev_extensions;

    VkDevice dev = nullptr;
    if (create_dev(chosen, &dci, nullptr, &dev) == VK_SUCCESS && dev) {
        gpu_info_.bda_supported = true;
        gpu_info_.bindless_supported = true;
    } else {
        // Fallback with just BDA
        bda_features.pNext = nullptr;
        if (create_dev(chosen, &dci, nullptr, &dev) == VK_SUCCESS && dev) {
            gpu_info_.bda_supported = true;
        } else {
            // Fallback with just swapchain
            dci.pNext = nullptr;
            dci.enabledExtensionCount = 1;
            if (create_dev(chosen, &dci, nullptr, &dev) != VK_SUCCESS || !dev) {
                dci.enabledExtensionCount = 0;
                dci.ppEnabledExtensionNames = nullptr;
                create_dev(chosen, &dci, nullptr, &dev);
            }
        }
    }

    if (dev) {
        vk_device_ = dev;
        gpu_info_.device_created = true;

        using PFN_vkGetDeviceQueue = void (VKAPI_PTR*)(VkDevice, uint32_t, uint32_t, void**);
        auto get_queue = reinterpret_cast<PFN_vkGetDeviceQueue>(get_proc(inst, "vkGetDeviceQueue"));
        if (get_queue) {
            get_queue(dev, 0, 0, &vk_queue_);
        }
        if (gpu_info_.bindless_supported) {
            InitializeBindlessHeap();
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

bool VulkanHostBackend::ExecuteCompute(
    const std::vector<uint32_t>& spirv_words,
    uint32_t groups_x,
    uint32_t groups_y,
    uint32_t groups_z) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vk_queue_ || !vulkan_dll_ || spirv_words.empty()) return false;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_sm = reinterpret_cast<PFN_vkCreateShaderModule>(get_proc(vk_instance_, "vkCreateShaderModule"));
    auto destroy_sm = reinterpret_cast<PFN_vkDestroyShaderModule>(get_proc(vk_instance_, "vkDestroyShaderModule"));
    auto create_pl = reinterpret_cast<PFN_vkCreatePipelineLayout>(get_proc(vk_instance_, "vkCreatePipelineLayout"));
    auto destroy_pl = reinterpret_cast<PFN_vkDestroyPipelineLayout>(get_proc(vk_instance_, "vkDestroyPipelineLayout"));
    auto create_cp = reinterpret_cast<PFN_vkCreateComputePipelines>(get_proc(vk_instance_, "vkCreateComputePipelines"));
    auto destroy_pip = reinterpret_cast<PFN_vkDestroyPipeline>(get_proc(vk_instance_, "vkDestroyPipeline"));
    auto create_pool = reinterpret_cast<PFN_vkCreateCommandPool>(get_proc(vk_instance_, "vkCreateCommandPool"));
    auto destroy_pool = reinterpret_cast<PFN_vkDestroyCommandPool>(get_proc(vk_instance_, "vkDestroyCommandPool"));
    auto alloc_cb = reinterpret_cast<PFN_vkAllocateCommandBuffers>(get_proc(vk_instance_, "vkAllocateCommandBuffers"));
    auto begin_cb = reinterpret_cast<PFN_vkBeginCommandBuffer>(get_proc(vk_instance_, "vkBeginCommandBuffer"));
    auto end_cb = reinterpret_cast<PFN_vkEndCommandBuffer>(get_proc(vk_instance_, "vkEndCommandBuffer"));
    auto bind_pip = reinterpret_cast<PFN_vkCmdBindPipeline>(get_proc(vk_instance_, "vkCmdBindPipeline"));
    auto cmd_dispatch = reinterpret_cast<PFN_vkCmdDispatch>(get_proc(vk_instance_, "vkCmdDispatch"));
    auto queue_submit = reinterpret_cast<PFN_vkQueueSubmit>(get_proc(vk_instance_, "vkQueueSubmit"));
    auto queue_wait = reinterpret_cast<PFN_vkQueueWaitIdle>(get_proc(vk_instance_, "vkQueueWaitIdle"));

    if (!create_sm || !destroy_sm || !create_pl || !destroy_pl || !create_cp || !destroy_pip ||
        !create_pool || !destroy_pool || !alloc_cb || !begin_cb || !end_cb || !bind_pip ||
        !cmd_dispatch || !queue_submit || !queue_wait) {
        return false;
    }

    // 1. Create Shader Module
    VkShaderModuleCreateInfo sm_ci{};
    sm_ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm_ci.codeSize = spirv_words.size() * sizeof(uint32_t);
    sm_ci.pCode = spirv_words.data();
    VkShaderModule mod = 0;
    if (create_sm(vk_device_, &sm_ci, nullptr, &mod) != VK_SUCCESS || !mod) return false;

    // 2. Create Pipeline Layout
    VkPipelineLayoutCreateInfo pl_ci{};
    pl_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    VkPipelineLayout layout = 0;
    if (create_pl(vk_device_, &pl_ci, nullptr, &layout) != VK_SUCCESS || !layout) {
        destroy_sm(vk_device_, mod, nullptr);
        return false;
    }

    // 3. Create Compute Pipeline
    VkComputePipelineCreateInfo cp_ci{};
    cp_ci.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp_ci.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cp_ci.stage.stage = 0x00000020; // VK_SHADER_STAGE_COMPUTE_BIT
    cp_ci.stage.module = mod;
    cp_ci.stage.pName = "main";
    cp_ci.layout = layout;
    VkPipeline pipeline = 0;
    if (create_cp(vk_device_, 0, 1, &cp_ci, nullptr, &pipeline) != VK_SUCCESS || !pipeline) {
        destroy_pl(vk_device_, layout, nullptr);
        destroy_sm(vk_device_, mod, nullptr);
        return false;
    }

    // 4. Create Command Pool
    VkCommandPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.flags = 0x00000002; // VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT
    pool_ci.queueFamilyIndex = queue_family_index_;
    VkCommandPool pool = 0;
    if (create_pool(vk_device_, &pool_ci, nullptr, &pool) != VK_SUCCESS || !pool) {
        destroy_pip(vk_device_, pipeline, nullptr);
        destroy_pl(vk_device_, layout, nullptr);
        destroy_sm(vk_device_, mod, nullptr);
        return false;
    }

    // 5. Allocate Command Buffer
    VkCommandBufferAllocateInfo cb_ai{};
    cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cb_ai.commandPool = pool;
    cb_ai.level = 0; // VK_COMMAND_BUFFER_LEVEL_PRIMARY
    cb_ai.commandBufferCount = 1;
    VkCommandBuffer cmd_buf = nullptr;
    if (alloc_cb(vk_device_, &cb_ai, &cmd_buf) != VK_SUCCESS || !cmd_buf) {
        destroy_pool(vk_device_, pool, nullptr);
        destroy_pip(vk_device_, pipeline, nullptr);
        destroy_pl(vk_device_, layout, nullptr);
        destroy_sm(vk_device_, mod, nullptr);
        return false;
    }

    // 6. Record & Dispatch
    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = 0x00000001; // VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT
    begin_cb(cmd_buf, &begin_info);
    bind_pip(cmd_buf, 1 /* VK_PIPELINE_BIND_POINT_COMPUTE */, pipeline);
    cmd_dispatch(cmd_buf, groups_x, groups_y, groups_z);
    end_cb(cmd_buf);

    // 7. Submit & Wait
    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buf;
    queue_submit(vk_queue_, 1, &submit_info, 0);
    queue_wait(vk_queue_);

    // 8. Cleanup
    destroy_pool(vk_device_, pool, nullptr);
    destroy_pip(vk_device_, pipeline, nullptr);
    destroy_pl(vk_device_, layout, nullptr);
    destroy_sm(vk_device_, mod, nullptr);
    ++gpu_info_.compute_dispatches_executed;
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::ExecuteDraw(
    uint32_t vertex_count,
    uint32_t instance_count,
    uint32_t first_vertex,
    uint32_t first_instance) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vk_queue_ || !vulkan_dll_ || vertex_count == 0) return false;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_pool = reinterpret_cast<PFN_vkCreateCommandPool>(get_proc(vk_instance_, "vkCreateCommandPool"));
    auto destroy_pool = reinterpret_cast<PFN_vkDestroyCommandPool>(get_proc(vk_instance_, "vkDestroyCommandPool"));
    auto alloc_cb = reinterpret_cast<PFN_vkAllocateCommandBuffers>(get_proc(vk_instance_, "vkAllocateCommandBuffers"));
    auto begin_cb = reinterpret_cast<PFN_vkBeginCommandBuffer>(get_proc(vk_instance_, "vkBeginCommandBuffer"));
    auto end_cb = reinterpret_cast<PFN_vkEndCommandBuffer>(get_proc(vk_instance_, "vkEndCommandBuffer"));
    auto cmd_draw = reinterpret_cast<PFN_vkCmdDraw>(get_proc(vk_instance_, "vkCmdDraw"));
    auto queue_submit = reinterpret_cast<PFN_vkQueueSubmit>(get_proc(vk_instance_, "vkQueueSubmit"));
    auto queue_wait = reinterpret_cast<PFN_vkQueueWaitIdle>(get_proc(vk_instance_, "vkQueueWaitIdle"));

    if (!create_pool || !destroy_pool || !alloc_cb || !begin_cb || !end_cb || !cmd_draw || !queue_submit || !queue_wait) {
        return false;
    }

    VkCommandPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.flags = 0x00000002;
    pool_ci.queueFamilyIndex = queue_family_index_;
    VkCommandPool pool = 0;
    if (create_pool(vk_device_, &pool_ci, nullptr, &pool) != VK_SUCCESS || !pool) return false;

    VkCommandBufferAllocateInfo cb_ai{};
    cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cb_ai.commandPool = pool;
    cb_ai.level = 0;
    cb_ai.commandBufferCount = 1;
    VkCommandBuffer cmd_buf = nullptr;
    if (alloc_cb(vk_device_, &cb_ai, &cmd_buf) != VK_SUCCESS || !cmd_buf) {
        destroy_pool(vk_device_, pool, nullptr);
        return false;
    }

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = 0x00000001;
    begin_cb(cmd_buf, &begin_info);
    cmd_draw(cmd_buf, vertex_count, instance_count, first_vertex, first_instance);
    end_cb(cmd_buf);

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buf;
    queue_submit(vk_queue_, 1, &submit_info, 0);
    queue_wait(vk_queue_);

    destroy_pool(vk_device_, pool, nullptr);
    ++gpu_info_.draw_calls_executed;
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::ExecuteDrawIndexed(
    uint32_t index_count,
    uint32_t instance_count,
    uint32_t first_index,
    int32_t vertex_offset,
    uint32_t first_instance) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vk_queue_ || !vulkan_dll_ || index_count == 0) return false;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_pool = reinterpret_cast<PFN_vkCreateCommandPool>(get_proc(vk_instance_, "vkCreateCommandPool"));
    auto destroy_pool = reinterpret_cast<PFN_vkDestroyCommandPool>(get_proc(vk_instance_, "vkDestroyCommandPool"));
    auto alloc_cb = reinterpret_cast<PFN_vkAllocateCommandBuffers>(get_proc(vk_instance_, "vkAllocateCommandBuffers"));
    auto begin_cb = reinterpret_cast<PFN_vkBeginCommandBuffer>(get_proc(vk_instance_, "vkBeginCommandBuffer"));
    auto end_cb = reinterpret_cast<PFN_vkEndCommandBuffer>(get_proc(vk_instance_, "vkEndCommandBuffer"));
    auto cmd_draw_idx = reinterpret_cast<PFN_vkCmdDrawIndexed>(get_proc(vk_instance_, "vkCmdDrawIndexed"));
    auto queue_submit = reinterpret_cast<PFN_vkQueueSubmit>(get_proc(vk_instance_, "vkQueueSubmit"));
    auto queue_wait = reinterpret_cast<PFN_vkQueueWaitIdle>(get_proc(vk_instance_, "vkQueueWaitIdle"));

    if (!create_pool || !destroy_pool || !alloc_cb || !begin_cb || !end_cb || !cmd_draw_idx || !queue_submit || !queue_wait) {
        return false;
    }

    VkCommandPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.flags = 0x00000002;
    pool_ci.queueFamilyIndex = queue_family_index_;
    VkCommandPool pool = 0;
    if (create_pool(vk_device_, &pool_ci, nullptr, &pool) != VK_SUCCESS || !pool) return false;

    VkCommandBufferAllocateInfo cb_ai{};
    cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cb_ai.commandPool = pool;
    cb_ai.level = 0;
    cb_ai.commandBufferCount = 1;
    VkCommandBuffer cmd_buf = nullptr;
    if (alloc_cb(vk_device_, &cb_ai, &cmd_buf) != VK_SUCCESS || !cmd_buf) {
        destroy_pool(vk_device_, pool, nullptr);
        return false;
    }

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = 0x00000001;
    begin_cb(cmd_buf, &begin_info);
    cmd_draw_idx(cmd_buf, index_count, instance_count, first_index, vertex_offset, first_instance);
    end_cb(cmd_buf);

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buf;
    queue_submit(vk_queue_, 1, &submit_info, 0);
    queue_wait(vk_queue_);

    destroy_pool(vk_device_, pool, nullptr);
    ++gpu_info_.draw_calls_executed;
    return true;
#else
    return false;
#endif
}

GpuBufferAllocation VulkanHostBackend::AllocateBufferWithDeviceAddress(
    uint64_t size,
    uint32_t usage_flags,
    bool host_visible) {
    GpuBufferAllocation alloc{};
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vulkan_dll_ || size == 0) return alloc;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return alloc;

    auto get_dev_proc = reinterpret_cast<void* (VKAPI_PTR*)(VkDevice, const char*)>(
        get_proc(vk_instance_, "vkGetDeviceProcAddr"));

    auto create_buf = reinterpret_cast<PFN_vkCreateBuffer>(get_proc(vk_instance_, "vkCreateBuffer"));
    auto destroy_buf = reinterpret_cast<PFN_vkDestroyBuffer>(get_proc(vk_instance_, "vkDestroyBuffer"));
    auto get_reqs = reinterpret_cast<PFN_vkGetBufferMemoryRequirements>(get_proc(vk_instance_, "vkGetBufferMemoryRequirements"));
    auto alloc_mem = reinterpret_cast<PFN_vkAllocateMemory>(get_proc(vk_instance_, "vkAllocateMemory"));
    auto free_mem = reinterpret_cast<PFN_vkFreeMemory>(get_proc(vk_instance_, "vkFreeMemory"));
    auto bind_buf = reinterpret_cast<PFN_vkBindBufferMemory>(get_proc(vk_instance_, "vkBindBufferMemory"));
    auto map_mem = reinterpret_cast<PFN_vkMapMemory>(get_proc(vk_instance_, "vkMapMemory"));
    
    PFN_vkGetBufferDeviceAddress get_bda = nullptr;
    if (get_dev_proc) {
        get_bda = reinterpret_cast<PFN_vkGetBufferDeviceAddress>(get_dev_proc(vk_device_, "vkGetBufferDeviceAddress"));
        if (!get_bda) {
            get_bda = reinterpret_cast<PFN_vkGetBufferDeviceAddress>(get_dev_proc(vk_device_, "vkGetBufferDeviceAddressKHR"));
        }
    }
    if (!get_bda) {
        get_bda = reinterpret_cast<PFN_vkGetBufferDeviceAddress>(get_proc(vk_instance_, "vkGetBufferDeviceAddress"));
    }
    if (!get_bda) {
        get_bda = reinterpret_cast<PFN_vkGetBufferDeviceAddress>(get_proc(vk_instance_, "vkGetBufferDeviceAddressKHR"));
    }
    auto get_mem_props = reinterpret_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(
        get_proc(vk_instance_, "vkGetPhysicalDeviceMemoryProperties"));

    if (!create_buf || !destroy_buf || !get_reqs || !alloc_mem || !free_mem || !bind_buf || !get_mem_props) {
        std::cerr << "  [BDA ERROR] Missing required buffer/memory proc addresses\n";
        return alloc;
    }

    VkBufferCreateInfo bci{};
    bci.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bci.size = (size + 255ULL) & ~255ULL;
    // VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT = 0x00020000
    bci.usage = usage_flags | 0x00020000U;

    uint64_t buffer = 0;
    VkResult rc_buf = create_buf(vk_device_, &bci, nullptr, &buffer);
    if (rc_buf != VK_SUCCESS || !buffer) {
        std::cerr << "  [BDA ERROR] vkCreateBuffer failed rc=" << rc_buf << "\n";
        return alloc;
    }

    VkMemoryRequirements reqs{};
    get_reqs(vk_device_, buffer, &reqs);

    VkPhysicalDeviceMemoryProperties mem_props{};
    get_mem_props(vk_phys_device_, &mem_props);
    uint32_t desired_flags = host_visible ? (0x00000002U /* HOST_VISIBLE */ | 0x00000004U /* HOST_COHERENT */)
                                          : 0x00000001U /* DEVICE_LOCAL */;

    VkMemoryAllocateFlagsInfo flags_info{};
    flags_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO;
    flags_info.flags = 0x00000002U; // VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT

    VkMemoryAllocateInfo mai{};
    mai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    mai.pNext = &flags_info;
    mai.allocationSize = reqs.size;

    uint64_t memory = 0;
    VkResult rc_mem = static_cast<VkResult>(-1);

    // 1. First attempt: match requested properties (e.g. host-visible + coherent)
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((reqs.memoryTypeBits & (1U << i)) && (mem_props.memoryTypes[i].propertyFlags & desired_flags) == desired_flags) {
            mai.memoryTypeIndex = i;
            rc_mem = alloc_mem(vk_device_, &mai, nullptr, &memory);
            if (rc_mem == VK_SUCCESS && memory) break;
        }
    }

    // 2. Fallback: on NVIDIA hardware, BDA allocations often require DEVICE_LOCAL memory
    if (rc_mem != VK_SUCCESS || !memory) {
        for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
            if ((reqs.memoryTypeBits & (1U << i)) && (mem_props.memoryTypes[i].propertyFlags & 0x00000001U /* DEVICE_LOCAL */)) {
                mai.memoryTypeIndex = i;
                rc_mem = alloc_mem(vk_device_, &mai, nullptr, &memory);
                if (rc_mem == VK_SUCCESS && memory) {
                    host_visible = false;
                    break;
                }
            }
        }
    }

    // 3. Last resort: try any type allowed by memoryTypeBits
    if (rc_mem != VK_SUCCESS || !memory) {
        for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
            if (reqs.memoryTypeBits & (1U << i)) {
                mai.memoryTypeIndex = i;
                rc_mem = alloc_mem(vk_device_, &mai, nullptr, &memory);
                if (rc_mem == VK_SUCCESS && memory) {
                    if (!(mem_props.memoryTypes[i].propertyFlags & 0x00000002U /* HOST_VISIBLE */)) {
                        host_visible = false;
                    }
                    break;
                }
            }
        }
    }

    if (rc_mem != VK_SUCCESS || !memory) {
        std::cerr << "  [BDA ERROR] vkAllocateMemory failed rc=" << rc_mem << "\n";
        destroy_buf(vk_device_, buffer, nullptr);
        return alloc;
    }

    VkResult rc_bind = bind_buf(vk_device_, buffer, memory, 0);
    if (rc_bind != VK_SUCCESS) {
        std::cerr << "  [BDA ERROR] vkBindBufferMemory failed rc=" << rc_bind << "\n";
        free_mem(vk_device_, memory, nullptr);
        destroy_buf(vk_device_, buffer, nullptr);
        return alloc;
    }

    uint64_t dev_addr = 0;
    if (get_bda) {
        VkBufferDeviceAddressInfo bdai{};
        bdai.sType = VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO;
        bdai.buffer = buffer;
        dev_addr = get_bda(vk_device_, &bdai);
    } else {
        std::cerr << "  [BDA ERROR] vkGetBufferDeviceAddress pointer null\n";
    }

    void* mapped = nullptr;
    if (host_visible && map_mem) {
        map_mem(vk_device_, memory, 0, reqs.size, 0, &mapped);
    }

    alloc.buffer_handle = buffer;
    alloc.memory_handle = memory;
    alloc.device_address = dev_addr;
    alloc.size = reqs.size;
    alloc.host_mapped_ptr = mapped;
    ++gpu_info_.bda_buffers_allocated;
#endif
    return alloc;
}

void VulkanHostBackend::FreeBufferWithDeviceAddress(const GpuBufferAllocation& alloc) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vulkan_dll_) return;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return;

    if (alloc.host_mapped_ptr) {
        auto unmap_mem = reinterpret_cast<PFN_vkUnmapMemory>(get_proc(vk_instance_, "vkUnmapMemory"));
        if (unmap_mem) unmap_mem(vk_device_, alloc.memory_handle);
    }
    if (alloc.buffer_handle) {
        auto destroy_buf = reinterpret_cast<PFN_vkDestroyBuffer>(get_proc(vk_instance_, "vkDestroyBuffer"));
        if (destroy_buf) destroy_buf(vk_device_, alloc.buffer_handle, nullptr);
    }
    if (alloc.memory_handle) {
        auto free_mem = reinterpret_cast<PFN_vkFreeMemory>(get_proc(vk_instance_, "vkFreeMemory"));
        if (free_mem) free_mem(vk_device_, alloc.memory_handle, nullptr);
    }
    if (gpu_info_.bda_buffers_allocated > 0) {
        --gpu_info_.bda_buffers_allocated;
    }
#endif
}

uint64_t VulkanHostBackend::GetBufferDeviceAddress(uint64_t buffer_handle) const {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vulkan_dll_ || !buffer_handle) return 0;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return 0;
    auto get_bda = reinterpret_cast<PFN_vkGetBufferDeviceAddress>(get_proc(vk_instance_, "vkGetBufferDeviceAddress"));
    if (!get_bda) {
        get_bda = reinterpret_cast<PFN_vkGetBufferDeviceAddress>(get_proc(vk_instance_, "vkGetBufferDeviceAddressKHR"));
    }
    if (!get_bda) return 0;
    VkBufferDeviceAddressInfo bdai{};
    bdai.sType = VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO;
    bdai.buffer = buffer_handle;
    return get_bda(vk_device_, &bdai);
#else
    return 0;
#endif
}

bool VulkanHostBackend::CreateDefaultGraphicsPipeline() {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vulkan_dll_) return false;
    if (default_graphics_pipeline_) return true;

    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_sm = reinterpret_cast<PFN_vkCreateShaderModule>(get_proc(vk_instance_, "vkCreateShaderModule"));
    auto destroy_sm = reinterpret_cast<PFN_vkDestroyShaderModule>(get_proc(vk_instance_, "vkDestroyShaderModule"));
    auto create_pl = reinterpret_cast<PFN_vkCreatePipelineLayout>(get_proc(vk_instance_, "vkCreatePipelineLayout"));
    auto create_rp = reinterpret_cast<PFN_vkCreateRenderPass>(get_proc(vk_instance_, "vkCreateRenderPass"));
    auto create_gp = reinterpret_cast<PFN_vkCreateGraphicsPipelines>(get_proc(vk_instance_, "vkCreateGraphicsPipelines"));

    if (!create_sm || !destroy_sm || !create_pl || !create_rp || !create_gp) return false;

    // 1. Compile minimal Vertex and Fragment modules
    auto vs_words = Rdna2ShaderAnalyzer::EmitMinimalSpirvVertex();
    auto fs_words = Rdna2ShaderAnalyzer::EmitMinimalSpirvFragment();

    VkShaderModuleCreateInfo vs_ci{};
    vs_ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    vs_ci.codeSize = vs_words.size() * sizeof(uint32_t);
    vs_ci.pCode = vs_words.data();
    VkShaderModule vs_mod = 0;
    VkResult rc_vs = create_sm(vk_device_, &vs_ci, nullptr, &vs_mod);
    if (rc_vs != VK_SUCCESS || !vs_mod) {
        std::cerr << "  [VK GP ERROR] vs create_sm failed rc=" << rc_vs << "\n";
        return false;
    }

    VkShaderModuleCreateInfo fs_ci{};
    fs_ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    fs_ci.codeSize = fs_words.size() * sizeof(uint32_t);
    fs_ci.pCode = fs_words.data();
    VkShaderModule fs_mod = 0;
    VkResult rc_fs = create_sm(vk_device_, &fs_ci, nullptr, &fs_mod);
    if (rc_fs != VK_SUCCESS || !fs_mod) {
        std::cerr << "  [VK GP ERROR] fs create_sm failed rc=" << rc_fs << "\n";
        destroy_sm(vk_device_, vs_mod, nullptr);
        return false;
    }

    // 2. Create Pipeline Layout
    VkPipelineLayoutCreateInfo pl_ci{};
    pl_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    VkPipelineLayout layout = 0;
    VkResult rc_pl = create_pl(vk_device_, &pl_ci, nullptr, &layout);
    if (rc_pl != VK_SUCCESS || !layout) {
        std::cerr << "  [VK GP ERROR] create_pl failed rc=" << rc_pl << "\n";
        destroy_sm(vk_device_, vs_mod, nullptr);
        destroy_sm(vk_device_, fs_mod, nullptr);
        return false;
    }
    default_pipeline_layout_ = layout;

    // 3. Create minimal RenderPass (1 color attachment matching fragment shader location 0)
    VkAttachmentDescription color_att{};
    color_att.flags = 0;
    color_att.format = 44; // VK_FORMAT_B8G8R8A8_UNORM
    color_att.samples = 1; // VK_SAMPLE_COUNT_1_BIT
    color_att.loadOp = 2;  // VK_ATTACHMENT_LOAD_OP_DONT_CARE
    color_att.storeOp = 1; // VK_ATTACHMENT_STORE_OP_DONT_CARE
    color_att.stencilLoadOp = 2;  // DONT_CARE
    color_att.stencilStoreOp = 1; // DONT_CARE
    color_att.initialLayout = 0; // VK_IMAGE_LAYOUT_UNDEFINED
    color_att.finalLayout = 2;   // VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL

    VkAttachmentReference color_ref{};
    color_ref.attachment = 0;
    color_ref.layout = 2; // VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL

    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = 0; // VK_PIPELINE_BIND_POINT_GRAPHICS
    subpass.colorAttachmentCount = 1;
    subpass.pColorAttachments = &color_ref;

    VkRenderPassCreateInfo rp_ci{};
    rp_ci.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rp_ci.attachmentCount = 1;
    rp_ci.pAttachments = &color_att;
    rp_ci.subpassCount = 1;
    rp_ci.pSubpasses = &subpass;

    uint64_t rp = 0;
    VkResult rc_rp = create_rp(vk_device_, &rp_ci, nullptr, &rp);
    if (rc_rp != VK_SUCCESS || !rp) {
        std::cerr << "  [VK GP ERROR] create_rp failed rc=" << rc_rp << "\n";
        destroy_sm(vk_device_, vs_mod, nullptr);
        destroy_sm(vk_device_, fs_mod, nullptr);
        return false;
    }
    default_render_pass_ = rp;

    // 4. Create Graphics Pipeline
    VkPipelineShaderStageCreateInfo stages[2]{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = 0x00000001; // VK_SHADER_STAGE_VERTEX_BIT
    stages[0].module = vs_mod;
    stages[0].pName = "main";

    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = 0x00000010; // VK_SHADER_STAGE_FRAGMENT_BIT
    stages[1].module = fs_mod;
    stages[1].pName = "main";

    VkPipelineVertexInputStateCreateInfo vi_ci{};
    vi_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;

    VkPipelineInputAssemblyStateCreateInfo ia_ci{};
    ia_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    ia_ci.topology = 3; // VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST

    VkViewport viewport{0.0f, 0.0f, 1920.0f, 1080.0f, 0.0f, 1.0f};
    VkRect2D scissor{{0, 0}, {1920, 1080}};
    VkPipelineViewportStateCreateInfo vp_ci{};
    vp_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    vp_ci.viewportCount = 1;
    vp_ci.pViewports = &viewport;
    vp_ci.scissorCount = 1;
    vp_ci.pScissors = &scissor;

    VkPipelineRasterizationStateCreateInfo rast_ci{};
    rast_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    rast_ci.polygonMode = 0; // VK_POLYGON_MODE_FILL
    rast_ci.cullMode = 0;    // VK_CULL_MODE_NONE
    rast_ci.frontFace = 0;   // VK_FRONT_FACE_COUNTER_CLOCKWISE
    rast_ci.lineWidth = 1.0f;

    VkPipelineMultisampleStateCreateInfo ms_ci{};
    ms_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    ms_ci.rasterizationSamples = 1; // VK_SAMPLE_COUNT_1_BIT

    VkPipelineColorBlendAttachmentState cb_att{};
    cb_att.blendEnable = 0;
    cb_att.colorWriteMask = 0x0000000FU; // VK_COLOR_COMPONENT_R_BIT | G | B | A (1|2|4|8)

    VkPipelineColorBlendStateCreateInfo cb_ci{};
    cb_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    cb_ci.attachmentCount = 1;
    cb_ci.pAttachments = &cb_att;

    uint32_t dyn_states[] = { 0 /* VK_DYNAMIC_STATE_VIEWPORT */, 1 /* VK_DYNAMIC_STATE_SCISSOR */ };
    VkPipelineDynamicStateCreateInfo dyn_ci{};
    dyn_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;
    dyn_ci.dynamicStateCount = 2;
    dyn_ci.pDynamicStates = dyn_states;

    VkGraphicsPipelineCreateInfo gp_ci{};
    gp_ci.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    gp_ci.stageCount = 2;
    gp_ci.pStages = stages;
    gp_ci.pVertexInputState = &vi_ci;
    gp_ci.pInputAssemblyState = &ia_ci;
    gp_ci.pViewportState = &vp_ci;
    gp_ci.pRasterizationState = &rast_ci;
    gp_ci.pMultisampleState = &ms_ci;
    gp_ci.pColorBlendState = &cb_ci;
    gp_ci.pDynamicState = &dyn_ci;
    gp_ci.layout = layout;
    gp_ci.renderPass = rp;
    gp_ci.subpass = 0;
    gp_ci.basePipelineIndex = -1;

    VkPipeline pipeline = 0;
    VkResult rc = create_gp(vk_device_, 0, 1, &gp_ci, nullptr, &pipeline);
    destroy_sm(vk_device_, vs_mod, nullptr);
    destroy_sm(vk_device_, fs_mod, nullptr);

    if (rc != VK_SUCCESS || !pipeline) {
        std::cerr << "  [VK GP ERROR] create_gp failed rc=" << rc << "\n";
        return false;
    }
    default_graphics_pipeline_ = pipeline;
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::ExecuteGraphicsDraw(
    uint32_t vertex_count,
    uint32_t instance_count,
    uint32_t first_vertex,
    uint32_t first_instance) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vk_queue_ || !vulkan_dll_ || vertex_count == 0) return false;
    if (!default_graphics_pipeline_) {
        if (!CreateDefaultGraphicsPipeline()) return false;
    }

    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_pool = reinterpret_cast<PFN_vkCreateCommandPool>(get_proc(vk_instance_, "vkCreateCommandPool"));
    auto destroy_pool = reinterpret_cast<PFN_vkDestroyCommandPool>(get_proc(vk_instance_, "vkDestroyCommandPool"));
    auto alloc_cb = reinterpret_cast<PFN_vkAllocateCommandBuffers>(get_proc(vk_instance_, "vkAllocateCommandBuffers"));
    auto begin_cb = reinterpret_cast<PFN_vkBeginCommandBuffer>(get_proc(vk_instance_, "vkBeginCommandBuffer"));
    auto end_cb = reinterpret_cast<PFN_vkEndCommandBuffer>(get_proc(vk_instance_, "vkEndCommandBuffer"));
    auto bind_pip = reinterpret_cast<PFN_vkCmdBindPipeline>(get_proc(vk_instance_, "vkCmdBindPipeline"));
    auto cmd_set_vp = reinterpret_cast<PFN_vkCmdSetViewport>(get_proc(vk_instance_, "vkCmdSetViewport"));
    auto cmd_set_sc = reinterpret_cast<PFN_vkCmdSetScissor>(get_proc(vk_instance_, "vkCmdSetScissor"));
    auto cmd_draw = reinterpret_cast<PFN_vkCmdDraw>(get_proc(vk_instance_, "vkCmdDraw"));
    auto queue_submit = reinterpret_cast<PFN_vkQueueSubmit>(get_proc(vk_instance_, "vkQueueSubmit"));
    auto queue_wait = reinterpret_cast<PFN_vkQueueWaitIdle>(get_proc(vk_instance_, "vkQueueWaitIdle"));

    if (!create_pool || !destroy_pool || !alloc_cb || !begin_cb || !end_cb || !bind_pip || !cmd_draw || !queue_submit || !queue_wait) {
        return false;
    }

    VkCommandPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.flags = 0x00000002;
    pool_ci.queueFamilyIndex = queue_family_index_;
    VkCommandPool pool = 0;
    if (create_pool(vk_device_, &pool_ci, nullptr, &pool) != VK_SUCCESS || !pool) return false;

    VkCommandBufferAllocateInfo cb_ai{};
    cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cb_ai.commandPool = pool;
    cb_ai.level = 0;
    cb_ai.commandBufferCount = 1;
    VkCommandBuffer cmd_buf = nullptr;
    if (alloc_cb(vk_device_, &cb_ai, &cmd_buf) != VK_SUCCESS || !cmd_buf) {
        destroy_pool(vk_device_, pool, nullptr);
        return false;
    }

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = 0x00000001;
    begin_cb(cmd_buf, &begin_info);

    bind_pip(cmd_buf, 0 /* VK_PIPELINE_BIND_POINT_GRAPHICS */, default_graphics_pipeline_);

    if (cmd_set_vp) {
        VkViewport vp{0.0f, 0.0f, 1920.0f, 1080.0f, 0.0f, 1.0f};
        cmd_set_vp(cmd_buf, 0, 1, &vp);
    }
    if (cmd_set_sc) {
        VkRect2D sc{{0, 0}, {1920, 1080}};
        cmd_set_sc(cmd_buf, 0, 1, &sc);
    }

    cmd_draw(cmd_buf, vertex_count, instance_count, first_vertex, first_instance);
    end_cb(cmd_buf);

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buf;
    queue_submit(vk_queue_, 1, &submit_info, 0);
    queue_wait(vk_queue_);

    destroy_pool(vk_device_, pool, nullptr);
    ++gpu_info_.draw_calls_executed;
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::CreateMultiStageGraphicsPipeline(
    const std::vector<uint32_t>& vs_spirv,
    const std::vector<uint32_t>& fs_spirv) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vulkan_dll_) return false;
    if (vs_spirv.empty() || fs_spirv.empty()) return false;

    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_sm = reinterpret_cast<PFN_vkCreateShaderModule>(get_proc(vk_instance_, "vkCreateShaderModule"));
    auto destroy_sm = reinterpret_cast<PFN_vkDestroyShaderModule>(get_proc(vk_instance_, "vkDestroyShaderModule"));
    auto create_pl = reinterpret_cast<PFN_vkCreatePipelineLayout>(get_proc(vk_instance_, "vkCreatePipelineLayout"));
    auto create_rp = reinterpret_cast<PFN_vkCreateRenderPass>(get_proc(vk_instance_, "vkCreateRenderPass"));
    auto create_gp = reinterpret_cast<PFN_vkCreateGraphicsPipelines>(get_proc(vk_instance_, "vkCreateGraphicsPipelines"));

    if (!create_sm || !destroy_sm || !create_pl || !create_rp || !create_gp) return false;

    // 1. Create Shader Modules
    VkShaderModuleCreateInfo vs_ci{};
    vs_ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    vs_ci.codeSize = vs_spirv.size() * sizeof(uint32_t);
    vs_ci.pCode = vs_spirv.data();
    VkShaderModule vs_mod = 0;
    if (create_sm(vk_device_, &vs_ci, nullptr, &vs_mod) != VK_SUCCESS || !vs_mod) return false;

    VkShaderModuleCreateInfo fs_ci{};
    fs_ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    fs_ci.codeSize = fs_spirv.size() * sizeof(uint32_t);
    fs_ci.pCode = fs_spirv.data();
    VkShaderModule fs_mod = 0;
    if (create_sm(vk_device_, &fs_ci, nullptr, &fs_mod) != VK_SUCCESS || !fs_mod) {
        destroy_sm(vk_device_, vs_mod, nullptr);
        return false;
    }

    // 2. Create Multi-stage Pipeline Layout with Bindless Descriptor Set 1 attached
    VkPipelineLayoutCreateInfo pl_ci{};
    pl_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    if (bindless_desc_layout_) {
        pl_ci.setLayoutCount = 1;
        pl_ci.pSetLayouts = &bindless_desc_layout_;
    }

    VkPipelineLayout layout = 0;
    if (create_pl(vk_device_, &pl_ci, nullptr, &layout) != VK_SUCCESS || !layout) {
        destroy_sm(vk_device_, vs_mod, nullptr);
        destroy_sm(vk_device_, fs_mod, nullptr);
        return false;
    }
    multi_stage_pipeline_layout_ = layout;

    // 3. Ensure render pass exists
    if (!default_render_pass_) {
        VkAttachmentDescription color_att{};
        color_att.flags = 0;
        color_att.format = 44; // VK_FORMAT_B8G8R8A8_UNORM
        color_att.samples = 1;
        color_att.loadOp = 2;  // DONT_CARE
        color_att.storeOp = 1; // DONT_CARE
        color_att.stencilLoadOp = 2;
        color_att.stencilStoreOp = 1;
        color_att.initialLayout = 0;
        color_att.finalLayout = 2; // COLOR_ATTACHMENT_OPTIMAL

        VkAttachmentReference color_ref{};
        color_ref.attachment = 0;
        color_ref.layout = 2;

        VkSubpassDescription subpass{};
        subpass.pipelineBindPoint = 0;
        subpass.colorAttachmentCount = 1;
        subpass.pColorAttachments = &color_ref;

        VkRenderPassCreateInfo rp_ci{};
        rp_ci.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
        rp_ci.attachmentCount = 1;
        rp_ci.pAttachments = &color_att;
        rp_ci.subpassCount = 1;
        rp_ci.pSubpasses = &subpass;

        create_rp(vk_device_, &rp_ci, nullptr, &default_render_pass_);
    }

    // 4. Create Multi-stage Graphics Pipeline
    VkPipelineShaderStageCreateInfo stages[2]{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = 0x00000001; // VK_SHADER_STAGE_VERTEX_BIT
    stages[0].module = vs_mod;
    stages[0].pName = "main";

    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = 0x00000010; // VK_SHADER_STAGE_FRAGMENT_BIT
    stages[1].module = fs_mod;
    stages[1].pName = "main";

    VkPipelineVertexInputStateCreateInfo vi_ci{};
    vi_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;

    VkPipelineInputAssemblyStateCreateInfo ia_ci{};
    ia_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    ia_ci.topology = 3; // VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST

    VkViewport viewport{0.0f, 0.0f, 1920.0f, 1080.0f, 0.0f, 1.0f};
    VkRect2D scissor{{0, 0}, {1920, 1080}};
    VkPipelineViewportStateCreateInfo vp_ci{};
    vp_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    vp_ci.viewportCount = 1;
    vp_ci.pViewports = &viewport;
    vp_ci.scissorCount = 1;
    vp_ci.pScissors = &scissor;

    VkPipelineRasterizationStateCreateInfo rast_ci{};
    rast_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    rast_ci.polygonMode = 0; // FILL
    rast_ci.cullMode = 0;    // NONE
    rast_ci.frontFace = 0;   // CCW
    rast_ci.lineWidth = 1.0f;

    VkPipelineMultisampleStateCreateInfo ms_ci{};
    ms_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    ms_ci.rasterizationSamples = 1;

    VkPipelineColorBlendAttachmentState cb_att{};
    cb_att.blendEnable = 0;
    cb_att.colorWriteMask = 0x0000000FU;

    VkPipelineColorBlendStateCreateInfo cb_ci{};
    cb_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    cb_ci.attachmentCount = 1;
    cb_ci.pAttachments = &cb_att;

    uint32_t dyn_states[] = { 0, 1 };
    VkPipelineDynamicStateCreateInfo dyn_ci{};
    dyn_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;
    dyn_ci.dynamicStateCount = 2;
    dyn_ci.pDynamicStates = dyn_states;

    VkGraphicsPipelineCreateInfo gp_ci{};
    gp_ci.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    gp_ci.stageCount = 2;
    gp_ci.pStages = stages;
    gp_ci.pVertexInputState = &vi_ci;
    gp_ci.pInputAssemblyState = &ia_ci;
    gp_ci.pViewportState = &vp_ci;
    gp_ci.pRasterizationState = &rast_ci;
    gp_ci.pMultisampleState = &ms_ci;
    gp_ci.pColorBlendState = &cb_ci;
    gp_ci.pDynamicState = &dyn_ci;
    gp_ci.layout = layout;
    gp_ci.renderPass = default_render_pass_;
    gp_ci.subpass = 0;
    gp_ci.basePipelineIndex = -1;

    VkPipeline pipeline = 0;
    VkResult rc = create_gp(vk_device_, 0, 1, &gp_ci, nullptr, &pipeline);
    destroy_sm(vk_device_, vs_mod, nullptr);
    destroy_sm(vk_device_, fs_mod, nullptr);

    if (rc != VK_SUCCESS || !pipeline) {
        std::cerr << "  [VK GP ERROR] create_gp failed rc=" << rc << "\n";
        return false;
    }
    multi_stage_graphics_pipeline_ = pipeline;
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::ExecuteMultiStageDrawIndexed(
    uint32_t index_count,
    uint32_t instance_count,
    uint32_t first_index,
    int32_t vertex_offset,
    uint32_t first_instance) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vk_queue_ || !vulkan_dll_ || index_count == 0) return false;
    if (!multi_stage_graphics_pipeline_) return false;

    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_pool = reinterpret_cast<PFN_vkCreateCommandPool>(get_proc(vk_instance_, "vkCreateCommandPool"));
    auto destroy_pool = reinterpret_cast<PFN_vkDestroyCommandPool>(get_proc(vk_instance_, "vkDestroyCommandPool"));
    auto alloc_cb = reinterpret_cast<PFN_vkAllocateCommandBuffers>(get_proc(vk_instance_, "vkAllocateCommandBuffers"));
    auto begin_cb = reinterpret_cast<PFN_vkBeginCommandBuffer>(get_proc(vk_instance_, "vkBeginCommandBuffer"));
    auto end_cb = reinterpret_cast<PFN_vkEndCommandBuffer>(get_proc(vk_instance_, "vkEndCommandBuffer"));
    auto bind_pip = reinterpret_cast<PFN_vkCmdBindPipeline>(get_proc(vk_instance_, "vkCmdBindPipeline"));
    auto bind_ds = reinterpret_cast<PFN_vkCmdBindDescriptorSets>(get_proc(vk_instance_, "vkCmdBindDescriptorSets"));
    auto cmd_set_vp = reinterpret_cast<PFN_vkCmdSetViewport>(get_proc(vk_instance_, "vkCmdSetViewport"));
    auto cmd_set_sc = reinterpret_cast<PFN_vkCmdSetScissor>(get_proc(vk_instance_, "vkCmdSetScissor"));
    auto cmd_draw_idx = reinterpret_cast<PFN_vkCmdDrawIndexed>(get_proc(vk_instance_, "vkCmdDrawIndexed"));
    auto queue_submit = reinterpret_cast<PFN_vkQueueSubmit>(get_proc(vk_instance_, "vkQueueSubmit"));
    auto queue_wait = reinterpret_cast<PFN_vkQueueWaitIdle>(get_proc(vk_instance_, "vkQueueWaitIdle"));

    if (!create_pool || !destroy_pool || !alloc_cb || !begin_cb || !end_cb || !bind_pip || !cmd_draw_idx || !queue_submit || !queue_wait) {
        return false;
    }

    VkCommandPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.flags = 0x00000002;
    pool_ci.queueFamilyIndex = queue_family_index_;
    VkCommandPool pool = 0;
    if (create_pool(vk_device_, &pool_ci, nullptr, &pool) != VK_SUCCESS || !pool) return false;

    VkCommandBufferAllocateInfo cb_ai{};
    cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cb_ai.commandPool = pool;
    cb_ai.level = 0;
    cb_ai.commandBufferCount = 1;
    VkCommandBuffer cmd_buf = nullptr;
    if (alloc_cb(vk_device_, &cb_ai, &cmd_buf) != VK_SUCCESS || !cmd_buf) {
        destroy_pool(vk_device_, pool, nullptr);
        return false;
    }

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = 0x00000001;
    begin_cb(cmd_buf, &begin_info);

    bind_pip(cmd_buf, 0 /* VK_PIPELINE_BIND_POINT_GRAPHICS */, multi_stage_graphics_pipeline_);

    if (bind_ds && bindless_descriptor_set_ && multi_stage_pipeline_layout_) {
        bind_ds(cmd_buf, 0 /* GRAPHICS */, multi_stage_pipeline_layout_, 0, 1, &bindless_descriptor_set_, 0, nullptr);
    }

    if (cmd_set_vp) {
        VkViewport vp{0.0f, 0.0f, 1920.0f, 1080.0f, 0.0f, 1.0f};
        cmd_set_vp(cmd_buf, 0, 1, &vp);
    }
    if (cmd_set_sc) {
        VkRect2D sc{{0, 0}, {1920, 1080}};
        cmd_set_sc(cmd_buf, 0, 1, &sc);
    }

    cmd_draw_idx(cmd_buf, index_count, instance_count, first_index, vertex_offset, first_instance);
    end_cb(cmd_buf);

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buf;
    queue_submit(vk_queue_, 1, &submit_info, 0);
    queue_wait(vk_queue_);

    destroy_pool(vk_device_, pool, nullptr);
    ++gpu_info_.draw_calls_executed;
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::InitializeBindlessHeap() {
#ifdef _WIN32
    if (!vk_device_ || !vulkan_dll_) return false;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_dsl = reinterpret_cast<PFN_vkCreateDescriptorSetLayout>(get_proc(vk_instance_, "vkCreateDescriptorSetLayout"));
    auto create_dp = reinterpret_cast<PFN_vkCreateDescriptorPool>(get_proc(vk_instance_, "vkCreateDescriptorPool"));
    auto alloc_ds = reinterpret_cast<PFN_vkAllocateDescriptorSets>(get_proc(vk_instance_, "vkAllocateDescriptorSets"));
    auto create_pl = reinterpret_cast<PFN_vkCreatePipelineLayout>(get_proc(vk_instance_, "vkCreatePipelineLayout"));

    if (!create_dsl || !create_dp || !alloc_ds || !create_pl) return false;

    // Binding 0: 1024 Sampled Images (Textures)
    // Binding 1: 64 Samplers
    VkDescriptorSetLayoutBinding bindings[2]{};
    bindings[0].binding = 0;
    bindings[0].descriptorType = 2; // VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE
    bindings[0].descriptorCount = 1024;
    bindings[0].stageFlags = 0x7FFFFFFF; // ALL stages

    bindings[1].binding = 1;
    bindings[1].descriptorType = 0; // VK_DESCRIPTOR_TYPE_SAMPLER
    bindings[1].descriptorCount = 64;
    bindings[1].stageFlags = 0x7FFFFFFF;

    uint32_t binding_flags[2] = {
        VK_DESCRIPTOR_BINDING_PARTIALLY_BOUND_BIT | VK_DESCRIPTOR_BINDING_UPDATE_AFTER_BIND_BIT,
        VK_DESCRIPTOR_BINDING_PARTIALLY_BOUND_BIT | VK_DESCRIPTOR_BINDING_UPDATE_AFTER_BIND_BIT
    };

    VkDescriptorSetLayoutBindingFlagsCreateInfo flags_info{};
    flags_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO;
    flags_info.bindingCount = 2;
    flags_info.pBindingFlags = binding_flags;

    VkDescriptorSetLayoutCreateInfo layout_ci{};
    layout_ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layout_ci.pNext = &flags_info;
    layout_ci.flags = 0x00000002; // VK_DESCRIPTOR_SET_LAYOUT_CREATE_UPDATE_AFTER_BIND_POOL_BIT
    layout_ci.bindingCount = 2;
    layout_ci.pBindings = bindings;

    if (create_dsl(vk_device_, &layout_ci, nullptr, &bindless_desc_layout_) != VK_SUCCESS || !bindless_desc_layout_) {
        return false;
    }

    // Create Descriptor Pool with UpdateAfterBind
    VkDescriptorPoolSize pool_sizes[2]{};
    pool_sizes[0].type = 2; // SAMPLED_IMAGE
    pool_sizes[0].descriptorCount = 1024;
    pool_sizes[1].type = 0; // SAMPLER
    pool_sizes[1].descriptorCount = 64;

    VkDescriptorPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pool_ci.flags = VK_DESCRIPTOR_POOL_CREATE_UPDATE_AFTER_BIND_BIT;
    pool_ci.maxSets = 4;
    pool_ci.poolSizeCount = 2;
    pool_ci.pPoolSizes = pool_sizes;

    if (create_dp(vk_device_, &pool_ci, nullptr, &bindless_desc_pool_) != VK_SUCCESS || !bindless_desc_pool_) {
        return false;
    }

    // Allocate Set 1
    VkDescriptorSetAllocateInfo ds_ai{};
    ds_ai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ds_ai.descriptorPool = bindless_desc_pool_;
    ds_ai.descriptorSetCount = 1;
    ds_ai.pSetLayouts = &bindless_desc_layout_;

    if (alloc_ds(vk_device_, &ds_ai, &bindless_descriptor_set_) != VK_SUCCESS || !bindless_descriptor_set_) {
        return false;
    }

    // Create Bindless Pipeline Layout
    VkPipelineLayoutCreateInfo pl_ci{};
    pl_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl_ci.setLayoutCount = 1;
    pl_ci.pSetLayouts = &bindless_desc_layout_;

    create_pl(vk_device_, &pl_ci, nullptr, &bindless_pipeline_layout_);
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::RegisterBindlessTexture(uint32_t slot, uint64_t image_view, uint32_t image_layout) {
#ifdef _WIN32
    if (!vk_device_ || !bindless_descriptor_set_) return false;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;
    auto update_desc = reinterpret_cast<PFN_vkUpdateDescriptorSets>(get_proc(vk_instance_, "vkUpdateDescriptorSets"));
    if (!update_desc) return false;

    VkDescriptorImageInfo img_info{};
    img_info.sampler = 0;
    img_info.imageView = image_view;
    img_info.imageLayout = image_layout;

    VkWriteDescriptorSet write{};
    write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    write.dstSet = bindless_descriptor_set_;
    write.dstBinding = 0;
    write.dstArrayElement = slot;
    write.descriptorCount = 1;
    write.descriptorType = 2; // VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE
    write.pImageInfo = &img_info;

    update_desc(vk_device_, 1, &write, 0, nullptr);
    ++gpu_info_.bindless_textures_registered;
    return true;
#else
    return false;
#endif
}

bool VulkanHostBackend::RegisterBindlessSampler(uint32_t slot, uint64_t sampler) {
#ifdef _WIN32
    if (!vk_device_ || !bindless_descriptor_set_) return false;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;
    auto update_desc = reinterpret_cast<PFN_vkUpdateDescriptorSets>(get_proc(vk_instance_, "vkUpdateDescriptorSets"));
    if (!update_desc) return false;

    VkDescriptorImageInfo samp_info{};
    samp_info.sampler = sampler;
    samp_info.imageView = 0;
    samp_info.imageLayout = 0;

    VkWriteDescriptorSet write{};
    write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    write.dstSet = bindless_descriptor_set_;
    write.dstBinding = 1;
    write.dstArrayElement = slot;
    write.descriptorCount = 1;
    write.descriptorType = 0; // VK_DESCRIPTOR_TYPE_SAMPLER
    write.pImageInfo = &samp_info;

    update_desc(vk_device_, 1, &write, 0, nullptr);
    ++gpu_info_.bindless_samplers_registered;
    return true;
#else
    return false;
#endif
}

uint64_t VulkanHostBackend::CreateTexture2D(
    uint32_t width,
    uint32_t height,
    uint32_t vk_format,
    const void* initial_data,
    size_t data_size,
    uint64_t* out_view) {
#ifdef _WIN32
    if (!vk_device_ || !vulkan_dll_) return 0;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return 0;

    auto create_img = reinterpret_cast<PFN_vkCreateImage>(get_proc(vk_instance_, "vkCreateImage"));
    auto get_reqs = reinterpret_cast<PFN_vkGetImageMemoryRequirements>(get_proc(vk_instance_, "vkGetImageMemoryRequirements"));
    auto alloc_mem = reinterpret_cast<PFN_vkAllocateMemory>(get_proc(vk_instance_, "vkAllocateMemory"));
    auto bind_mem = reinterpret_cast<PFN_vkBindImageMemory>(get_proc(vk_instance_, "vkBindImageMemory"));
    auto create_iv = reinterpret_cast<PFN_vkCreateImageView>(get_proc(vk_instance_, "vkCreateImageView"));

    if (!create_img || !get_reqs || !alloc_mem || !bind_mem || !create_iv) return 0;

    struct {
        uint32_t sType;
        const void* pNext;
        uint32_t flags;
        uint32_t imageType;
        uint32_t format;
        struct { uint32_t w; uint32_t h; uint32_t d; } extent;
        uint32_t mipLevels;
        uint32_t arrayLayers;
        uint32_t samples;
        uint32_t tiling;
        uint32_t usage;
        uint32_t sharingMode;
        uint32_t queueFamilyIndexCount;
        const uint32_t* pQueueFamilyIndices;
        uint32_t initialLayout;
    } img_ci{};

    img_ci.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    img_ci.imageType = 2; // 2D
    img_ci.format = vk_format;
    img_ci.extent = { width, height, 1 };
    img_ci.mipLevels = 1;
    img_ci.arrayLayers = 1;
    img_ci.samples = 1;
    img_ci.tiling = 0; // OPTIMAL
    img_ci.usage = 0x00000004 | 0x00000002; // VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT
    img_ci.sharingMode = 0;

    uint64_t image_handle = 0;
    if (create_img(vk_device_, &img_ci, nullptr, &image_handle) != VK_SUCCESS || !image_handle) {
        return 0;
    }

    VkMemoryRequirements reqs{};
    get_reqs(vk_device_, image_handle, &reqs);

    // Find memory type with DEVICE_LOCAL or HOST_VISIBLE
    auto get_mem_props = reinterpret_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(
        get_proc(vk_instance_, "vkGetPhysicalDeviceMemoryProperties"));
    VkPhysicalDeviceMemoryProperties mem_props{};
    get_mem_props(vk_phys_device_, &mem_props);

    uint32_t mem_type_idx = 0;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((reqs.memoryTypeBits & (1 << i)) &&
            (mem_props.memoryTypes[i].propertyFlags & 0x1U)) { // DEVICE_LOCAL
            mem_type_idx = i;
            break;
        }
    }

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = reqs.size;
    alloc_info.memoryTypeIndex = mem_type_idx;

    uint64_t image_mem = 0;
    if (alloc_mem(vk_device_, &alloc_info, nullptr, &image_mem) != VK_SUCCESS || !image_mem) {
        return 0;
    }

    bind_mem(vk_device_, image_handle, image_mem, 0);

    // Create View
    struct {
        uint32_t sType;
        const void* pNext;
        uint32_t flags;
        uint64_t image;
        uint32_t viewType;
        uint32_t format;
        struct { uint32_t r, g, b, a; } components;
        struct {
            uint32_t aspectMask;
            uint32_t baseMipLevel;
            uint32_t levelCount;
            uint32_t baseArrayLayer;
            uint32_t layerCount;
        } subresourceRange;
    } iv_ci{};

    iv_ci.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    iv_ci.image = image_handle;
    iv_ci.viewType = 1; // 2D
    iv_ci.format = vk_format;
    iv_ci.subresourceRange.aspectMask = 1; // COLOR
    iv_ci.subresourceRange.baseMipLevel = 0;
    iv_ci.subresourceRange.levelCount = 1;
    iv_ci.subresourceRange.baseArrayLayer = 0;
    iv_ci.subresourceRange.layerCount = 1;

    uint64_t view_handle = 0;
    if (create_iv(vk_device_, &iv_ci, nullptr, &view_handle) != VK_SUCCESS || !view_handle) {
        return 0;
    }

    if (out_view) *out_view = view_handle;
    return image_handle;
#else
    return 0;
#endif
}

uint64_t VulkanHostBackend::CreateDepthTargetImage(
    uint32_t width,
    uint32_t height,
    uint32_t vk_format,
    uint64_t* out_view) {
#ifdef _WIN32
    if (!vk_device_ || !vulkan_dll_) return 0;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return 0;

    auto create_img = reinterpret_cast<PFN_vkCreateImage>(get_proc(vk_instance_, "vkCreateImage"));
    auto get_reqs = reinterpret_cast<PFN_vkGetImageMemoryRequirements>(get_proc(vk_instance_, "vkGetImageMemoryRequirements"));
    auto alloc_mem = reinterpret_cast<PFN_vkAllocateMemory>(get_proc(vk_instance_, "vkAllocateMemory"));
    auto bind_mem = reinterpret_cast<PFN_vkBindImageMemory>(get_proc(vk_instance_, "vkBindImageMemory"));
    auto create_iv = reinterpret_cast<PFN_vkCreateImageView>(get_proc(vk_instance_, "vkCreateImageView"));

    if (!create_img || !get_reqs || !alloc_mem || !bind_mem || !create_iv) return 0;

    struct {
        uint32_t sType;
        const void* pNext;
        uint32_t flags;
        uint32_t imageType;
        uint32_t format;
        struct { uint32_t w; uint32_t h; uint32_t d; } extent;
        uint32_t mipLevels;
        uint32_t arrayLayers;
        uint32_t samples;
        uint32_t tiling;
        uint32_t usage;
        uint32_t sharingMode;
        uint32_t queueFamilyIndexCount;
        const uint32_t* pQueueFamilyIndices;
        uint32_t initialLayout;
    } img_ci{};

    img_ci.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    img_ci.imageType = 2; // 2D
    img_ci.format = vk_format;
    img_ci.extent = { width, height, 1 };
    img_ci.mipLevels = 1;
    img_ci.arrayLayers = 1;
    img_ci.samples = 1;
    img_ci.tiling = 0; // OPTIMAL
    // VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT (0x20) | VK_IMAGE_USAGE_SAMPLED_BIT (0x4) | VK_IMAGE_USAGE_TRANSFER_SRC_BIT (0x1) | VK_IMAGE_USAGE_TRANSFER_DST_BIT (0x2)
    img_ci.usage = 0x00000020 | 0x00000004 | 0x00000001 | 0x00000002;
    img_ci.sharingMode = 0;

    uint64_t image_handle = 0;
    if (create_img(vk_device_, &img_ci, nullptr, &image_handle) != VK_SUCCESS || !image_handle) {
        return 0;
    }

    VkMemoryRequirements reqs{};
    get_reqs(vk_device_, image_handle, &reqs);

    auto get_mem_props = reinterpret_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(
        get_proc(vk_instance_, "vkGetPhysicalDeviceMemoryProperties"));
    VkPhysicalDeviceMemoryProperties mem_props{};
    get_mem_props(vk_phys_device_, &mem_props);

    uint32_t mem_type_idx = 0;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((reqs.memoryTypeBits & (1 << i)) &&
            (mem_props.memoryTypes[i].propertyFlags & 0x1U)) { // DEVICE_LOCAL
            mem_type_idx = i;
            break;
        }
    }

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = reqs.size;
    alloc_info.memoryTypeIndex = mem_type_idx;

    uint64_t image_mem = 0;
    if (alloc_mem(vk_device_, &alloc_info, nullptr, &image_mem) != VK_SUCCESS || !image_mem) {
        return 0;
    }

    bind_mem(vk_device_, image_handle, image_mem, 0);

    // Create View
    struct {
        uint32_t sType;
        const void* pNext;
        uint32_t flags;
        uint64_t image;
        uint32_t viewType;
        uint32_t format;
        struct { uint32_t r, g, b, a; } components;
        struct {
            uint32_t aspectMask;
            uint32_t baseMipLevel;
            uint32_t levelCount;
            uint32_t baseArrayLayer;
            uint32_t layerCount;
        } subresourceRange;
    } iv_ci{};

    iv_ci.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    iv_ci.image = image_handle;
    iv_ci.viewType = 1; // 2D
    iv_ci.format = vk_format;
    iv_ci.subresourceRange.aspectMask = (vk_format >= 124 && vk_format <= 130) ? 2 /* DEPTH */ : 1 /* COLOR */;
    iv_ci.subresourceRange.baseMipLevel = 0;
    iv_ci.subresourceRange.levelCount = 1;
    iv_ci.subresourceRange.baseArrayLayer = 0;
    iv_ci.subresourceRange.layerCount = 1;

    uint64_t view_handle = 0;
    if (create_iv(vk_device_, &iv_ci, nullptr, &view_handle) != VK_SUCCESS || !view_handle) {
        return 0;
    }

    if (out_view) *out_view = view_handle;
    return image_handle;
#else
    return 0;
#endif
}

bool VulkanHostBackend::TransferImageToLinearBuffer(
    uint64_t src_image,
    uint64_t dst_buffer,
    uint32_t width,
    uint32_t height) {
#ifdef _WIN32
    if (!initialized_ || !vk_device_ || !vk_queue_ || !vulkan_dll_) return false;
    if (!src_image || !dst_buffer || width == 0 || height == 0) return false;

    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (!get_proc) return false;

    auto create_pool = reinterpret_cast<PFN_vkCreateCommandPool>(get_proc(vk_instance_, "vkCreateCommandPool"));
    auto destroy_pool = reinterpret_cast<PFN_vkDestroyCommandPool>(get_proc(vk_instance_, "vkDestroyCommandPool"));
    auto alloc_cb = reinterpret_cast<PFN_vkAllocateCommandBuffers>(get_proc(vk_instance_, "vkAllocateCommandBuffers"));
    auto begin_cb = reinterpret_cast<PFN_vkBeginCommandBuffer>(get_proc(vk_instance_, "vkBeginCommandBuffer"));
    auto end_cb = reinterpret_cast<PFN_vkEndCommandBuffer>(get_proc(vk_instance_, "vkEndCommandBuffer"));
    auto cmd_barrier = reinterpret_cast<PFN_vkCmdPipelineBarrier>(get_proc(vk_instance_, "vkCmdPipelineBarrier"));
    auto cmd_copy = reinterpret_cast<PFN_vkCmdCopyImageToBuffer>(get_proc(vk_instance_, "vkCmdCopyImageToBuffer"));
    auto queue_submit = reinterpret_cast<PFN_vkQueueSubmit>(get_proc(vk_instance_, "vkQueueSubmit"));
    auto queue_wait = reinterpret_cast<PFN_vkQueueWaitIdle>(get_proc(vk_instance_, "vkQueueWaitIdle"));

    if (!create_pool || !destroy_pool || !alloc_cb || !begin_cb || !end_cb || !cmd_barrier || !cmd_copy || !queue_submit || !queue_wait) {
        return false;
    }

    VkCommandPoolCreateInfo pool_ci{};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.flags = 0x00000002;
    pool_ci.queueFamilyIndex = queue_family_index_;
    VkCommandPool pool = 0;
    if (create_pool(vk_device_, &pool_ci, nullptr, &pool) != VK_SUCCESS || !pool) return false;

    VkCommandBufferAllocateInfo cb_ai{};
    cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cb_ai.commandPool = pool;
    cb_ai.level = 0;
    cb_ai.commandBufferCount = 1;
    VkCommandBuffer cmd_buf = nullptr;
    if (alloc_cb(vk_device_, &cb_ai, &cmd_buf) != VK_SUCCESS || !cmd_buf) {
        destroy_pool(vk_device_, pool, nullptr);
        return false;
    }

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = 0x00000001;
    begin_cb(cmd_buf, &begin_info);

    // 1. Transition Image: UNDEFINED -> TRANSFER_SRC_OPTIMAL
    VkImageMemoryBarrier barrier_pre{};
    barrier_pre.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    barrier_pre.srcAccessMask = 0;
    barrier_pre.dstAccessMask = 0x00000800; // VK_ACCESS_TRANSFER_READ_BIT
    barrier_pre.oldLayout = 0;             // VK_IMAGE_LAYOUT_UNDEFINED
    barrier_pre.newLayout = 6;             // VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL
    barrier_pre.srcQueueFamilyIndex = ~0U;
    barrier_pre.dstQueueFamilyIndex = ~0U;
    barrier_pre.image = src_image;
    barrier_pre.subresourceRange.aspectMask = 1; // COLOR
    barrier_pre.subresourceRange.baseMipLevel = 0;
    barrier_pre.subresourceRange.levelCount = 1;
    barrier_pre.subresourceRange.baseArrayLayer = 0;
    barrier_pre.subresourceRange.layerCount = 1;

    cmd_barrier(cmd_buf, 0x00000001 /* TOP_OF_PIPE */, 0x00001000 /* TRANSFER */, 0, 0, nullptr, 0, nullptr, 1, &barrier_pre);

    // 2. Copy Image to Buffer
    VkBufferImageCopy region{};
    region.bufferOffset = 0;
    region.bufferRowLength = 0;
    region.bufferImageHeight = 0;
    region.imageSubresource.aspectMask = 1;
    region.imageSubresource.mipLevel = 0;
    region.imageSubresource.baseArrayLayer = 0;
    region.imageSubresource.layerCount = 1;
    region.imageOffset = { 0, 0, 0 };
    region.imageExtent = { width, height, 1 };

    cmd_copy(cmd_buf, src_image, 6 /* TRANSFER_SRC_OPTIMAL */, dst_buffer, 1, &region);

    // 3. Post Barrier: Ensure TRANSFER_WRITE finishes before HOST_READ
    VkImageMemoryBarrier barrier_post{};
    barrier_post.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    barrier_post.srcAccessMask = 0x00000800; // TRANSFER_READ
    barrier_post.dstAccessMask = 0x00004000; // HOST_READ_BIT
    barrier_post.oldLayout = 6;              // TRANSFER_SRC_OPTIMAL
    barrier_post.newLayout = 5;              // SHADER_READ_ONLY_OPTIMAL
    barrier_post.srcQueueFamilyIndex = ~0U;
    barrier_post.dstQueueFamilyIndex = ~0U;
    barrier_post.image = src_image;
    barrier_post.subresourceRange = barrier_pre.subresourceRange;

    cmd_barrier(cmd_buf, 0x00001000 /* TRANSFER */, 0x00004000 /* HOST */, 0, 0, nullptr, 0, nullptr, 1, &barrier_post);

    end_cb(cmd_buf);

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buf;
    queue_submit(vk_queue_, 1, &submit_info, 0);
    queue_wait(vk_queue_);

    destroy_pool(vk_device_, pool, nullptr);
    return true;
#else
    return false;
#endif
}

void VulkanHostBackend::Shutdown() {
#ifdef _WIN32
    if (!initialized_ || !vulkan_dll_) return;
    auto get_proc = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        ::GetProcAddress(static_cast<HMODULE>(vulkan_dll_), "vkGetInstanceProcAddr"));
    if (get_proc && vk_device_) {
        if (bindless_pipeline_layout_) {
            auto destroy_pl = reinterpret_cast<PFN_vkDestroyPipelineLayout>(get_proc(vk_instance_, "vkDestroyPipelineLayout"));
            if (destroy_pl) destroy_pl(vk_device_, bindless_pipeline_layout_, nullptr);
            bindless_pipeline_layout_ = 0;
        }
        if (bindless_desc_pool_) {
            auto destroy_dp = reinterpret_cast<PFN_vkDestroyDescriptorPool>(get_proc(vk_instance_, "vkDestroyDescriptorPool"));
            if (destroy_dp) destroy_dp(vk_device_, bindless_desc_pool_, nullptr);
            bindless_desc_pool_ = 0;
        }
        if (bindless_desc_layout_) {
            auto destroy_dsl = reinterpret_cast<PFN_vkDestroyDescriptorSetLayout>(get_proc(vk_instance_, "vkDestroyDescriptorSetLayout"));
            if (destroy_dsl) destroy_dsl(vk_device_, bindless_desc_layout_, nullptr);
            bindless_desc_layout_ = 0;
        }
        if (multi_stage_graphics_pipeline_) {
            auto destroy_pip = reinterpret_cast<PFN_vkDestroyPipeline>(get_proc(vk_instance_, "vkDestroyPipeline"));
            if (destroy_pip) destroy_pip(vk_device_, multi_stage_graphics_pipeline_, nullptr);
            multi_stage_graphics_pipeline_ = 0;
        }
        if (multi_stage_pipeline_layout_) {
            auto destroy_pl = reinterpret_cast<PFN_vkDestroyPipelineLayout>(get_proc(vk_instance_, "vkDestroyPipelineLayout"));
            if (destroy_pl) destroy_pl(vk_device_, multi_stage_pipeline_layout_, nullptr);
            multi_stage_pipeline_layout_ = 0;
        }
        if (default_graphics_pipeline_) {
            auto destroy_pip = reinterpret_cast<PFN_vkDestroyPipeline>(get_proc(vk_instance_, "vkDestroyPipeline"));
            if (destroy_pip) destroy_pip(vk_device_, default_graphics_pipeline_, nullptr);
            default_graphics_pipeline_ = 0;
        }
        if (default_pipeline_layout_) {
            auto destroy_pl = reinterpret_cast<PFN_vkDestroyPipelineLayout>(get_proc(vk_instance_, "vkDestroyPipelineLayout"));
            if (destroy_pl) destroy_pl(vk_device_, default_pipeline_layout_, nullptr);
            default_pipeline_layout_ = 0;
        }
        if (default_render_pass_) {
            auto destroy_rp = reinterpret_cast<PFN_vkDestroyRenderPass>(get_proc(vk_instance_, "vkDestroyRenderPass"));
            if (destroy_rp) destroy_rp(vk_device_, default_render_pass_, nullptr);
            default_render_pass_ = 0;
        }
        auto destroy_dev = reinterpret_cast<PFN_vkDestroyDevice>(
            get_proc(vk_instance_, "vkDestroyDevice"));
        if (destroy_dev) destroy_dev(vk_device_, nullptr);
        vk_device_ = nullptr;
    }
    if (get_proc && vk_instance_) {
        auto destroy_inst = reinterpret_cast<PFN_vkDestroyInstance>(
            get_proc(vk_instance_, "vkDestroyInstance"));
        if (destroy_inst) destroy_inst(vk_instance_, nullptr);
        vk_instance_ = nullptr;
    }
    FreeLibrary(static_cast<HMODULE>(vulkan_dll_));
    vulkan_dll_ = nullptr;
    initialized_ = false;
#endif
}

} // namespace yotei::graphics
