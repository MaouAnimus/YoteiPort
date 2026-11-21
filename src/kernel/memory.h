#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yotei::kernel {

struct DirectMemoryBlock {
    uint64_t phys_offset;
    uint64_t size;
    uint32_t memory_type;
};

struct MappedRegion {
    uint64_t guest_vaddr;
    uint64_t size;
    uint64_t phys_offset;
    uint32_t prot;
    std::string name;
};

constexpr uint32_t SCE_KERNEL_PROT_NONE      = 0x00;
constexpr uint32_t SCE_KERNEL_PROT_CPU_READ  = 0x01;
constexpr uint32_t SCE_KERNEL_PROT_CPU_WRITE = 0x02;
constexpr uint32_t SCE_KERNEL_PROT_CPU_EXEC  = 0x04;
constexpr uint32_t SCE_KERNEL_PROT_GPU_READ  = 0x10;
constexpr uint32_t SCE_KERNEL_PROT_GPU_WRITE = 0x20;
constexpr uint32_t SCE_KERNEL_PROT_GPU_ALL   = 0x30;

// PS5 Prospero sceKernelBatchMap entry structure (40 bytes)
#pragma pack(push, 1)
struct SceKernelBatchMapEntry {
    uint64_t start_vaddr;
    uint64_t phys_offset;
    uint64_t length;
    uint8_t  prot;
    uint8_t  memory_type;
    uint16_t reserved;
    uint32_t flags;
    uint32_t operation;
    uint32_t pad;
};
#pragma pack(pop)

class GuestMemoryManager {
public:
    static GuestMemoryManager& Instance();

    uint64_t GetDirectMemorySize() const { return kTotalDirectMemorySize; }
    uint64_t GetFlexibleMemorySize() const { return kConfiguredFlexibleMemorySize; }

    // sceKernelAllocateDirectMemory(searchStart, searchEnd, len, alignment, memoryType, physAddrOut)
    int32_t AllocateDirectMemory(
        int64_t search_start,
        int64_t search_end,
        uint64_t len,
        uint64_t alignment,
        uint32_t memory_type,
        uint64_t* phys_addr_out);

    // sceKernelAllocateMainDirectMemory
    int32_t AllocateMainDirectMemory(
        uint64_t len,
        uint64_t alignment,
        uint32_t memory_type,
        uint64_t* phys_addr_out);

    // sceKernelReleaseDirectMemory & sceKernelCheckedReleaseDirectMemory
    int32_t ReleaseDirectMemory(uint64_t phys_addr, uint64_t len);

    // sceKernelMapDirectMemory / sceKernelMapNamedFlexibleMemory
    int32_t MapMemory(
        uint64_t* inout_vaddr,
        uint64_t len,
        uint32_t prot,
        uint32_t flags,
        uint64_t phys_offset,
        uint64_t alignment,
        const char* name = nullptr);

    // sceKernelBatchMap / sceKernelBatchMap2
    int32_t BatchMap(
        const SceKernelBatchMapEntry* entries,
        int32_t num_entries,
        int32_t* num_handled_out,
        uint32_t flags = 0);

    int32_t BatchMap2(
        const SceKernelBatchMapEntry* entries,
        int32_t num_entries,
        int32_t* num_handled_out,
        uint32_t flags = 0);

    // Annotate a mapped region (sceKernelSetVirtualRangeName)
    int32_t SetVirtualRangeName(uint64_t vaddr, uint64_t len, const char* name);

    // Physical <-> Virtual address translation
    uint64_t PhysToVirt(uint64_t phys_addr) const;
    uint64_t VirtToPhys(uint64_t virt_addr) const;

    [[nodiscard]] size_t GetTotalDirectBlocksCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return direct_blocks_.size();
    }
    [[nodiscard]] size_t GetTotalMappedRegionsCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return mapped_regions_.size();
    }

    void ReleaseAll();
    std::vector<MappedRegion> GetMappedRegions() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return mapped_regions_;
    }

private:
    GuestMemoryManager() = default;

    static constexpr uint64_t kTotalDirectMemorySize = 12ULL * 1024ULL * 1024ULL * 1024ULL; // 12 GiB
    static constexpr uint64_t kConfiguredFlexibleMemorySize = 165675008ULL;                 // 158 MiB (param.json)

    mutable std::mutex mutex_;
    uint64_t next_phys_offset_ = 0x10000000ULL;
    uint64_t next_auto_vaddr_  = 0x0000001000000000ULL;
    std::vector<DirectMemoryBlock> direct_blocks_;
    std::vector<MappedRegion> mapped_regions_;
};

} // namespace yotei::kernel
