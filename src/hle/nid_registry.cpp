#include "hle/nid_registry.h"
#include "kernel/filesystem.h"
#include "kernel/memory.h"
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::hle {

namespace {

struct BoundSlotMeta {
    std::string library;
    std::string nid;
    std::string resolved_name;
    uint64_t got_vaddr;
};

std::vector<BoundSlotMeta> g_bound_slots;
uint64_t g_guest_base = 0;
size_t g_call_counter = 0;
uint64_t g_stack_canary_value = 0x594f54454943414eULL; // "YOTEICAN"
uint64_t g_need_flag_value = 1;
uint64_t g_dummy_iob_object[16] = {0};

// SysV AMD64 ABI passes args in: RDI, RSI, RDX, RCX, R8, R9.
// Our generated 32-byte x86-64 trampoline translates a SysV call into MS x64 call:
//   RCX = slot_index
//   RDX = guest_rdi (arg1)
//   R8  = guest_rsi (arg2)
//   R9  = guest_rdx (arg3)
extern "C" uint64_t __fastcall HleDispatchTrampoline(
    uint64_t slot_index,
    uint64_t guest_rdi,
    uint64_t guest_rsi,
    uint64_t guest_rdx,
    uint64_t guest_rcx,
    uint64_t guest_r8,
    uint64_t guest_r9) {
    if (slot_index >= g_bound_slots.size()) return 0;
    const auto& meta = g_bound_slots[slot_index];
    ++g_call_counter;

    if (g_call_counter <= 120) {
        std::cout << "  [HLE #" << std::setw(2) << g_call_counter << "] "
                  << std::setw(18) << std::left << meta.library << " :: "
                  << std::setw(38) << meta.resolved_name
                  << " (" << meta.nid << ") | rdi=0x" << std::hex << guest_rdi
                  << " rsi=0x" << guest_rsi << " rdx=0x" << guest_rdx << std::dec << std::endl;
    }

    auto& mem_mgr = kernel::GuestMemoryManager::Instance();
    auto& vfs = kernel::VirtualFileSystem::Instance();

    // Specific early boot & kernel HLE handlers:
    if (meta.nid == "tU5e3f9gSiU" && meta.resolved_name.find("GetProcParam") != std::string::npos) {
        return g_guest_base + 0x1e7bfd8ULL;
    }
    if (meta.nid == "n1-v6FgU7MQ") {
        // sceKernelAvailableFlexibleMemorySize / ConfiguredFlexibleMemorySize
        if (guest_rdi != 0 && guest_rdi >= g_guest_base) {
            *reinterpret_cast<uint64_t*>(guest_rdi) = mem_mgr.GetFlexibleMemorySize();
        }
        return 0;
    }
    if (meta.nid == "pO96TwzOm5E") {
        // sceKernelGetDirectMemorySize
        return mem_mgr.GetDirectMemorySize();
    }
    if (meta.nid == "rTXw65xmLIA") {
        // sceKernelAllocateDirectMemory(searchStart, searchEnd, len, alignment, memoryType, physAddrOut)
        return static_cast<uint64_t>(mem_mgr.AllocateDirectMemory(
            static_cast<int64_t>(guest_rdi),
            static_cast<int64_t>(guest_rsi),
            guest_rdx,
            guest_rcx,
            static_cast<uint32_t>(guest_r8),
            reinterpret_cast<uint64_t*>(guest_r9)));
    }
    if (meta.nid == "2SKEx6bSq-4") {
        // sceKernelBatchMap(entries, numEntries, numHandledOut) / sceKernelBatchMap2
        return static_cast<uint64_t>(mem_mgr.BatchMap(
            reinterpret_cast<const kernel::SceKernelBatchMapEntry*>(guest_rdi),
            static_cast<int32_t>(guest_rsi),
            reinterpret_cast<int32_t*>(guest_rdx)));
    }
    if (meta.nid == "L-Q3LEjIbgA" || meta.nid == "NcaWUxfMNIQ") {
        // sceKernelMapDirectMemory / sceKernelMapNamedFlexibleMemory
        return static_cast<uint64_t>(mem_mgr.MapMemory(
            reinterpret_cast<uint64_t*>(guest_rdi),
            guest_rsi,
            static_cast<uint32_t>(guest_rdx),
            static_cast<uint32_t>(guest_rcx),
            guest_r8,
            guest_r9));
    }
    if (meta.nid == "-hn1tcVHq5Q") {
        // sceKernelSetVirtualRangeName(vaddr, len, name) or internal label helper(name, vaddr, len)
        if (guest_rdi >= g_guest_base && guest_rsi >= 0x100000000ULL) {
            mem_mgr.SetVirtualRangeName(guest_rsi, guest_rdx, reinterpret_cast<const char*>(guest_rdi));
        }
        return 0;
    }
    if (meta.nid == "1jfXLRVzisc" || meta.resolved_name == "FileSystem::KernelOpen") {
        return static_cast<uint64_t>(vfs.Open(
            reinterpret_cast<const char*>(guest_rdi),
            static_cast<int32_t>(guest_rsi),
            static_cast<int32_t>(guest_rdx)));
    }
    if (meta.resolved_name == "FileSystem::KernelRead") {
        return static_cast<uint64_t>(vfs.Read(
            static_cast<int32_t>(guest_rdi),
            reinterpret_cast<void*>(guest_rsi),
            guest_rdx));
    }
    if (meta.resolved_name == "FileSystem::KernelPread") {
        return static_cast<uint64_t>(vfs.Pread(
            static_cast<int32_t>(guest_rdi),
            reinterpret_cast<void*>(guest_rsi),
            guest_rdx,
            static_cast<int64_t>(guest_rcx)));
    }
    if (meta.resolved_name == "FileSystem::KernelClose") {
        return static_cast<uint64_t>(vfs.Close(static_cast<int32_t>(guest_rdi)));
    }
    if (meta.resolved_name == "FileSystem::KernelStat") {
        return static_cast<uint64_t>(vfs.Stat(
            reinterpret_cast<const char*>(guest_rdi),
            reinterpret_cast<kernel::SceKernelStat*>(guest_rsi)));
    }
    if (meta.resolved_name == "FileSystem::KernelFstat") {
        return static_cast<uint64_t>(vfs.Fstat(
            static_cast<int32_t>(guest_rdi),
            reinterpret_cast<kernel::SceKernelStat*>(guest_rsi)));
    }
    if (meta.nid == "9BcDykPmo1I") {
        // __error() -> thread-local errno pointer
        static thread_local int s_guest_errno = 0;
        return reinterpret_cast<uint64_t>(&s_guest_errno);
    }
    if (meta.nid == "3GPpjQdAMTw") {
        // __cxa_guard_acquire(uint64_t* guard_object) -> return 1 if not initialized yet
        if (guest_rdi != 0) {
            auto* guard_byte = reinterpret_cast<uint8_t*>(guest_rdi);
            if (*guard_byte == 0) {
                return 1;
            }
        }
        return 0;
    }
    if (meta.nid == "9rAeANT2tyE") {
        // __cxa_guard_release(uint64_t* guard_object)
        if (guest_rdi != 0) {
            *reinterpret_cast<uint8_t*>(guest_rdi) = 1;
        }
        return 0;
    }
    if (meta.nid == "2X5agFjKxMc") {
        // calloc(count, size)
        size_t total = static_cast<size_t>(guest_rdi * guest_rsi);
        if (total == 0 || total > (1ULL << 30)) total = 64;
        void* p = std::calloc(1, total);
        return reinterpret_cast<uint64_t>(p);
    }
    if (meta.nid == "reb+WcV3+0M" || meta.resolved_name == "LibC::malloc") {
        // malloc(size)
        size_t sz = static_cast<size_t>(guest_rdi);
        if (sz == 0 || sz > (1ULL << 30)) sz = 64;
        void* p = std::malloc(sz);
        return reinterpret_cast<uint64_t>(p);
    }
    if (meta.nid == "iF1iQHzxBJU" || meta.nid == "Vla-Z+eXlxo" || meta.nid == "AV6ipCNa4Rw") {
        // sce::Mspace::malloc(mspace, alignment, size) / memalign / allocate
        size_t sz = static_cast<size_t>(guest_rdx != 0 ? guest_rdx : (guest_rsi != 0 ? guest_rsi : guest_rdi));
        if (sz < 64 || sz > (1ULL << 28)) sz = 256;
        void* p = std::calloc(1, sz);
        return reinterpret_cast<uint64_t>(p);
    }
    if (meta.nid == "j4ViWNHEgww") {
        // strlen(const char* s)
        if (guest_rdi != 0) {
            return std::strlen(reinterpret_cast<const char*>(guest_rdi));
        }
        return 0;
    }
    if (meta.nid == "6sJWiWSRuqk") {
        // strncpy(char* dst, const char* src, size_t n)
        if (guest_rdi != 0 && guest_rsi != 0 && guest_rdx > 0 && guest_rdx < 65536) {
            std::strncpy(
                reinterpret_cast<char*>(guest_rdi),
                reinterpret_cast<const char*>(guest_rsi),
                static_cast<size_t>(guest_rdx));
        }
        return guest_rdi;
    }
    if (meta.nid == "Q3VBxCXhUHs") {
        // memcpy(void* dst, const void* src, size_t n)
        if (guest_rdi != 0 && guest_rsi != 0 && guest_rdx > 0 && guest_rdx < (1ULL << 28)) {
            std::memcpy(
                reinterpret_cast<void*>(guest_rdi),
                reinterpret_cast<const void*>(guest_rsi),
                static_cast<size_t>(guest_rdx));
        }
        return guest_rdi;
    }
    if (meta.nid == "8zsu04XNsZ4" || meta.resolved_name == "LibcInternal::memset") {
        // memset(void* dst, int c, size_t n)
        if (guest_rdi != 0 && guest_rdx > 0 && guest_rdx < (1ULL << 28)) {
            std::memset(
                reinterpret_cast<void*>(guest_rdi),
                static_cast<int>(guest_rsi),
                static_cast<size_t>(guest_rdx));
        }
        return guest_rdi;
    }
    if (meta.nid == "BfBDZGbti7A" || meta.nid == "tU5e3f9gSiU") {
        // AgcGetIsTrinityMode / KernelIsTrinityMode -> 0 (Standard PS5 Prospero)
        return 0;
    }
    if (meta.nid == "wRbq6ZjNop4" || meta.nid == "2JtWUUiYBXs" || meta.nid == "23LRUSvYu1M") {
        // AgcGetRegisterDefaults2Internal / AgcGetRegisterDefaults2 / AgcInit -> 0 (SCE_OK)
        if (meta.nid == "23LRUSvYu1M" && guest_rdi != 0 && guest_rdi >= g_guest_base) {
            *reinterpret_cast<uint32_t*>(guest_rdi) = 0;
        }
        return 0;
    }
    if (meta.nid == "1tKyG7RlMJo") {
        // scePthreadGetprio(thread, int* prio_out)
        if (guest_rsi != 0) {
            *reinterpret_cast<uint32_t*>(guest_rsi) = 256;
        }
        return 0;
    }
    if (meta.nid == "obuxdTiwkF8") {
        // sceNetCtlGetInfo(code, SceNetCtlInfo* info)
        if (guest_rsi != 0) {
            std::strcpy(reinterpret_cast<char*>(guest_rsi), "YoteiPC");
        }
        return 0;
    }
    return 0;
}

} // namespace

bool NidRegistry::LoadResolutionTable(const std::filesystem::path& json_path) {
    std::ifstream ifs(json_path);
    if (!ifs) return false;
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string content = buffer.str();

    std::regex entry_re(
        "\"nid\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*"
        "\"resolved_name\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*"
        "\"resolution_source\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*"
        "\"library\"\\s*:\\s*\"([^\"]+)\"");

    auto begin = std::sregex_iterator(content.begin(), content.end(), entry_re);
    auto end = std::sregex_iterator();

    table_.clear();
    for (auto it = begin; it != end; ++it) {
        NidEntry e;
        e.nid = (*it)[1].str();
        e.resolved_name = (*it)[2].str();
        e.resolution_source = (*it)[3].str();
        e.library = (*it)[4].str();
        table_[e.nid] = std::move(e);
    }
    return !table_.empty();
}

size_t NidRegistry::BindImportsToGuestGot(
    uint64_t guest_base,
    const std::vector<loader::ImportedSymbol>& imports) {
    g_guest_base = guest_base;
    g_bound_slots.clear();
    FreeTrampolines();

#ifdef _WIN32
    // Allocate 64-byte executable stub per import (SysV AMD64 -> MS x64 bridge preserving non-volatile regs)
    size_t slab_size = (imports.size() + 16) * 96;
    trampoline_slab_ = VirtualAlloc(
        nullptr, slab_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#endif
    if (!trampoline_slab_) return 0;

    auto* slab = reinterpret_cast<uint8_t*>(trampoline_slab_);
    size_t bound_count = 0;

    for (const auto& imp : imports) {
        if (imp.got_vaddr == 0) continue;
        uint32_t slot_idx = static_cast<uint32_t>(g_bound_slots.size());
        auto it = table_.find(imp.nid);
        std::string res_name = (it != table_.end()) ? it->second.resolved_name : ("sub_nid_" + imp.nid);

        g_bound_slots.push_back({imp.library, imp.nid, res_name, imp.got_vaddr});

        // Emit 96-byte SysV AMD64 -> Windows x64 bridge stub forwarding all 6 SysV args (RDI, RSI, RDX, RCX, R8, R9)
        uint8_t* stub = slab + slot_idx * 96;
        uint8_t code[] = {
            0x55,                                     // push rbp
            0x48, 0x89, 0xE5,                         // mov rbp, rsp
            0x57,                                     // push rdi
            0x56,                                     // push rsi
            0x48, 0x83, 0xE4, 0xF0,                   // and rsp, -16
            0x48, 0x83, 0xEC, 0x40,                   // sub rsp, 64 (32 shadow + 3 stack args + align)
            0x48, 0x89, 0x4C, 0x24, 0x20,             // mov [rsp+0x20], rcx (arg4 = guest_rcx)
            0x4C, 0x89, 0x44, 0x24, 0x28,             // mov [rsp+0x28], r8  (arg5 = guest_r8)
            0x4C, 0x89, 0x4C, 0x24, 0x30,             // mov [rsp+0x30], r9  (arg6 = guest_r9)
            0x49, 0x89, 0xD1,                         // mov r9, rdx         (arg3 = guest_rdx)
            0x49, 0x89, 0xF0,                         // mov r8, rsi         (arg2 = guest_rsi)
            0x48, 0x89, 0xFA,                         // mov rdx, rdi        (arg1 = guest_rdi)
            0xB9, 0x00, 0x00, 0x00, 0x00,             // mov ecx, slot_idx   (offset 39)
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,       // movabs rax, &HleDispatchTrampoline (offset 44)
            0xFF, 0xD0,                               // call rax
            0x48, 0x8D, 0x65, 0xF0,                   // lea rsp, [rbp - 16]
            0x5E,                                     // pop rsi
            0x5F,                                     // pop rdi
            0x5D,                                     // pop rbp
            0xC3                                      // ret
        };
        std::memcpy(code + 39, &slot_idx, sizeof(uint32_t));
        uint64_t fn_addr = reinterpret_cast<uint64_t>(&HleDispatchTrampoline);
        std::memcpy(code + 45, &fn_addr, sizeof(uint64_t));
        std::memcpy(stub, code, sizeof(code));

        auto* got_slot = reinterpret_cast<uint64_t*>(guest_base + imp.got_vaddr);
        // Handle R_X86_64_GLOB_DAT (type 6) and R_X86_64_64 (type 1) data pointers vs R_X86_64_JUMP_SLOT (type 7)
        if (imp.nid == "f7uOxY9mM1U") { // &LibKernel::g_stack_chk_guard
            *got_slot = reinterpret_cast<uint64_t>(&g_stack_canary_value);
        } else if (imp.nid == "P330P3dFF68") { // &LibC::g_need_flag
            *got_slot = reinterpret_cast<uint64_t>(&g_need_flag_value);
        } else if (imp.nid == "2sWzhYqFH4E" || imp.nid == "H8AprKeZtNg") { // stdout / stderr pointers
            *got_slot = reinterpret_cast<uint64_t>(&g_dummy_iob_object[0]);
        } else {
            *got_slot = reinterpret_cast<uint64_t>(stub);
        }
        if (it != table_.end()) {
            it->second.host_stub_address = *got_slot;
        }
        ++bound_count;
    }
    return bound_count;
}

const NidEntry* NidRegistry::Lookup(const std::string& nid) const {
    auto it = table_.find(nid);
    return (it != table_.end()) ? &it->second : nullptr;
}

void NidRegistry::FreeTrampolines() {
#ifdef _WIN32
    if (trampoline_slab_) {
        VirtualFree(trampoline_slab_, 0, MEM_RELEASE);
        trampoline_slab_ = nullptr;
    }
#endif
}

} // namespace yotei::hle
