#include "kernel/memory.h"
#include <algorithm>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::kernel {

GuestMemoryManager& GuestMemoryManager::Instance() {
    static GuestMemoryManager instance;
    return instance;
}

int32_t GuestMemoryManager::AllocateDirectMemory(
    int64_t /*search_start*/,
    int64_t /*search_end*/,
    uint64_t len,
    uint64_t alignment,
    uint32_t memory_type,
    uint64_t* phys_addr_out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (alignment < 0x10000ULL) alignment = 0x10000ULL;
    uint64_t aligned_phys = (next_phys_offset_ + (alignment - 1)) & ~(alignment - 1);
    next_phys_offset_ = aligned_phys + len;

    direct_blocks_.push_back({aligned_phys, len, memory_type});
    if (phys_addr_out) {
        *phys_addr_out = aligned_phys;
    }
    return 0; // SCE_OK
}

int32_t GuestMemoryManager::MapMemory(
    uint64_t* inout_vaddr,
    uint64_t len,
    uint32_t prot,
    uint32_t /*flags*/,
    uint64_t phys_offset,
    uint64_t alignment,
    const char* name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (len == 0) return -1;
    if (alignment < 0x10000ULL) alignment = 0x10000ULL;

    uint64_t req_vaddr = (inout_vaddr && *inout_vaddr != 0) ? *inout_vaddr : 0;
    if (req_vaddr == 0) {
        req_vaddr = (next_auto_vaddr_ + (alignment - 1)) & ~(alignment - 1);
    }

    uint64_t aligned_len = (len + 0xFFFFULL) & ~0xFFFFULL;

#ifdef _WIN32
    void* mem = VirtualAlloc(
        reinterpret_cast<void*>(req_vaddr),
        static_cast<SIZE_T>(aligned_len),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);
    if (!mem) {
        // Fallback: let Windows choose or advance next_auto_vaddr_
        while (!mem && next_auto_vaddr_ < 0x0000007000000000ULL) {
            next_auto_vaddr_ += 0x40000000ULL; // step 1 GiB
            mem = VirtualAlloc(
                reinterpret_cast<void*>(next_auto_vaddr_),
                static_cast<SIZE_T>(aligned_len),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE);
        }
        if (!mem) {
            mem = VirtualAlloc(
                nullptr,
                static_cast<SIZE_T>(aligned_len),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE);
        }
    }
    if (!mem) return -12; // SCE_KERNEL_ERROR_ENOMEM

    uint64_t actual_vaddr = reinterpret_cast<uint64_t>(mem);
    if (actual_vaddr + aligned_len > next_auto_vaddr_) {
        next_auto_vaddr_ = (actual_vaddr + aligned_len + 0xFFFFFULL) & ~0xFFFFFULL;
    }
    if (inout_vaddr) {
        *inout_vaddr = actual_vaddr;
    }

    mapped_regions_.push_back({
        actual_vaddr,
        aligned_len,
        phys_offset,
        prot,
        name ? std::string(name) : "direct_mem"
    });
    return 0;
#else
    return -1;
#endif
}

int32_t GuestMemoryManager::BatchMap(
    const SceKernelBatchMapEntry* entries,
    int32_t num_entries,
    int32_t* num_handled_out,
    uint32_t flags) {
    if (!entries || num_entries <= 0) {
        if (num_handled_out) *num_handled_out = 0;
        return 0;
    }
    int32_t handled = 0;
    for (int32_t i = 0; i < num_entries; ++i) {
        uint64_t vaddr = entries[i].start_vaddr;
        uint64_t len   = entries[i].length;
        if (len == 0) len = 0x26c00000ULL; // Fallback if entry layout differs
        int32_t rc = MapMemory(&vaddr, len, entries[i].prot, flags, entries[i].phys_offset, 0x10000ULL, "batch_map");
        if (rc != 0) break;
        ++handled;
    }
    if (num_handled_out) {
        *num_handled_out = handled;
    }
    return 0;
}

int32_t GuestMemoryManager::SetVirtualRangeName(uint64_t vaddr, uint64_t len, const char* name) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string label = name ? std::string(name) : "";
    for (auto& reg : mapped_regions_) {
        if (reg.guest_vaddr == vaddr || (vaddr >= reg.guest_vaddr && vaddr < reg.guest_vaddr + reg.size)) {
            reg.name = label;
            return 0;
        }
    }
    mapped_regions_.push_back({vaddr, len, 0, 0x3, label});
    return 0;
}

void GuestMemoryManager::ReleaseAll() {
    std::lock_guard<std::mutex> lock(mutex_);
#ifdef _WIN32
    for (const auto& reg : mapped_regions_) {
        if (reg.phys_offset != 0 || reg.name == "batch_map" || reg.name == "direct_mem" || reg.name == "CRT") {
            VirtualFree(reinterpret_cast<void*>(reg.guest_vaddr), 0, MEM_RELEASE);
        }
    }
#endif
    mapped_regions_.clear();
    direct_blocks_.clear();
}

} // namespace yotei::kernel
