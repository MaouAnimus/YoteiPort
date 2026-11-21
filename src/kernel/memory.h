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

    // sceKernelMapDirectMemory / sceKernelMapNamedFlexibleMemory
    int32_t MapMemory(
        uint64_t* inout_vaddr,
        uint64_t len,
        uint32_t prot,
        uint32_t flags,
        uint64_t phys_offset,
        uint64_t alignment,
        const char* name = nullptr);

    // sceKernelBatchMap(entries, numEntries, numHandledOut)
    int32_t BatchMap(
        const SceKernelBatchMapEntry* entries,
        int32_t num_entries,
        int32_t* num_handled_out,
        uint32_t flags = 0);

    // Annotate a mapped region (sceKernelSetVirtualRangeName)
    int32_t SetVirtualRangeName(uint64_t vaddr, uint64_t len, const char* name);

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
