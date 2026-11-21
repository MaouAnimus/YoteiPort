#include "hle/nid_registry.h"
#include "graphics/agc_driver_hle.h"
#include "graphics/pm4_decoder.h"
#include "graphics/video_out_hle.h"
#include "audio/audio_out_hle.h"
#include "audio/ajm_hle.h"
#include "audio/wasapi_backend.h"
#include "hle/ampr_hle.h"
#include "input/pad_hle.h"
#include "kernel/filesystem.h"
#include "kernel/memory.h"
#include "kernel/threads.h"
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <regex>
#include <sstream>
#include <unordered_set>
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

std::mutex g_unhandled_mutex;
std::unordered_map<std::string, UnhandledStubRecord> g_unhandled_stubs;
bool g_verbose_unhandled = false;

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

    // 1. Delegate AMPR / APR asynchronous streaming calls
    uint64_t sub_ret = 0;
    if (AmprHleManager::Instance().DispatchNid(
            meta.nid, meta.resolved_name,
            guest_rdi, guest_rsi, guest_rdx, guest_rcx, guest_r8, guest_r9, &sub_ret)) {
        return sub_ret;
    }

    // 2. Delegate libSceVideoOut / Swapchain presentation calls first
    if (graphics::VideoOutHleManager::Instance().DispatchNid(
            meta.library, meta.nid, meta.resolved_name,
            guest_rdi, guest_rsi, guest_rdx, guest_rcx, guest_r8, guest_r9, &sub_ret)) {
        return sub_ret;
    }

    // 2.2. Delegate libSceAgc & libSceAgcDriver Context / DCB / ACB calls
    if (graphics::AgcDriverHleManager::Instance().DispatchNid(
            meta.library, meta.nid, meta.resolved_name,
            guest_rdi, guest_rsi, guest_rdx, guest_rcx, guest_r8, guest_r9, &sub_ret)) {
        return sub_ret;
    }

    // 2.5. Delegate fallback AGC / PM4 calls
    if (graphics::AgcPm4Backend::Instance().DispatchNid(
            meta.library, meta.nid, meta.resolved_name,
            guest_rdi, guest_rsi, guest_rdx, guest_rcx, guest_r8, guest_r9, &sub_ret)) {
        return sub_ret;
    }

    // 3. Delegate Threading / Pthread / Mutex / Cond / Semaphore calls
    if (kernel::ThreadManager::Instance().DispatchNid(
            meta.nid, meta.resolved_name,
            guest_rdi, guest_rsi, guest_rdx, guest_rcx, guest_r8, guest_r9, &sub_ret)) {
        return sub_ret;
    }

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
    if (meta.nid == "B+vc2AO2Zrc") {
        // sceKernelAllocateMainDirectMemory(len, alignment, memoryType, physAddrOut)
        return static_cast<uint64_t>(mem_mgr.AllocateMainDirectMemory(
            guest_rdi,
            guest_rsi,
            static_cast<uint32_t>(guest_rdx),
            reinterpret_cast<uint64_t*>(guest_rcx)));
    }
    if (meta.nid == "MBuItvba6z8" || meta.nid == "hwVSPCmp5tM") {
        // sceKernelReleaseDirectMemory(physAddr, len) / sceKernelCheckedReleaseDirectMemory
        return static_cast<uint64_t>(mem_mgr.ReleaseDirectMemory(guest_rdi, guest_rsi));
    }
    if (meta.nid == "2SKEx6bSq-4") {
        // sceKernelBatchMap(entries, numEntries, numHandledOut)
        return static_cast<uint64_t>(mem_mgr.BatchMap(
            reinterpret_cast<const kernel::SceKernelBatchMapEntry*>(guest_rdi),
            static_cast<int32_t>(guest_rsi),
            reinterpret_cast<int32_t*>(guest_rdx)));
    }
    if (meta.nid == "kBJzF8x4SyE") {
        // sceKernelBatchMap2(entries, numEntries, numHandledOut, flags)
        return static_cast<uint64_t>(mem_mgr.BatchMap2(
            reinterpret_cast<const kernel::SceKernelBatchMapEntry*>(guest_rdi),
            static_cast<int32_t>(guest_rsi),
            reinterpret_cast<int32_t*>(guest_rdx),
            static_cast<uint32_t>(guest_rcx)));
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
    // Sleep operations
    if (meta.nid == "1jfXLRVzisc" || meta.resolved_name == "sceKernelUsleep" || meta.resolved_name == "usleep") {
        uint32_t usec = static_cast<uint32_t>(guest_rdi);
        if (usec >= 1000) {
            Sleep(usec / 1000);
        } else if (usec > 0) {
            Sleep(0); // Yield remainder of quantum
        }
        return 0; // SCE_OK
    }
    if (meta.nid == "QvsZxomvUHs" || meta.resolved_name == "sceKernelNanosleep" || meta.resolved_name == "nanosleep") {
        if (guest_rdi >= 0x1000) {
            struct SceTimespec { int64_t sec; int64_t nsec; };
            auto* ts = reinterpret_cast<const SceTimespec*>(guest_rdi);
            int64_t ms = ts->sec * 1000 + ts->nsec / 1000000;
            if (ms > 0) {
                Sleep(static_cast<DWORD>(ms));
            } else {
                Sleep(0);
            }
        }
        return 0; // SCE_OK
    }

    // File I/O operations
    if (meta.nid == "1G3lF1Gg1k8" || meta.resolved_name == "sceKernelOpen" || meta.resolved_name == "FileSystem::KernelOpen" || meta.resolved_name == "open") {
        if (guest_rdi < 0x1000) return static_cast<uint64_t>(-14); // EFAULT
        return static_cast<uint64_t>(vfs.Open(
            reinterpret_cast<const char*>(guest_rdi),
            static_cast<int32_t>(guest_rsi),
            static_cast<int32_t>(guest_rdx)));
    }
    if (meta.nid == "Cg4srZ6TKbU" || meta.resolved_name == "sceKernelRead" || meta.resolved_name == "FileSystem::KernelRead" || meta.resolved_name == "read") {
        if (guest_rsi < 0x1000) return static_cast<uint64_t>(-14);
        return static_cast<uint64_t>(vfs.Read(
            static_cast<int32_t>(guest_rdi),
            reinterpret_cast<void*>(guest_rsi),
            guest_rdx));
    }
    if (meta.resolved_name == "sceKernelPread" || meta.resolved_name == "FileSystem::KernelPread" || meta.resolved_name == "pread") {
        if (guest_rsi < 0x1000) return static_cast<uint64_t>(-14);
        return static_cast<uint64_t>(vfs.Pread(
            static_cast<int32_t>(guest_rdi),
            reinterpret_cast<void*>(guest_rsi),
            guest_rdx,
            static_cast<int64_t>(guest_rcx)));
    }
    if (meta.nid == "UK2Tl2DWUns" || meta.resolved_name == "sceKernelClose" || meta.resolved_name == "FileSystem::KernelClose" || meta.resolved_name == "close") {
        return static_cast<uint64_t>(vfs.Close(static_cast<int32_t>(guest_rdi)));
    }
    if (meta.nid == "eV9wAD2riIA" || meta.resolved_name == "sceKernelStat" || meta.resolved_name == "FileSystem::KernelStat" || meta.resolved_name == "stat") {
        if (guest_rdi < 0x1000 || guest_rsi < 0x1000) return static_cast<uint64_t>(-14);
        return static_cast<uint64_t>(vfs.Stat(
            reinterpret_cast<const char*>(guest_rdi),
            reinterpret_cast<kernel::SceKernelStat*>(guest_rsi)));
    }
    if (meta.nid == "kBwCPsYX-m4" || meta.resolved_name == "sceKernelFstat" || meta.resolved_name == "FileSystem::KernelFstat" || meta.resolved_name == "fstat") {
        if (guest_rsi < 0x1000) return static_cast<uint64_t>(-14);
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
        if (guest_rdi > 0x1000) {
            return std::strlen(reinterpret_cast<const char*>(guest_rdi));
        }
        return 0;
    }
    if (meta.nid == "6sJWiWSRuqk") {
        // strncpy(char* dst, const char* src, size_t n)
        if (guest_rdi > 0x1000 && guest_rsi > 0x1000 && guest_rdx > 0 && guest_rdx < 65536) {
            std::strncpy(
                reinterpret_cast<char*>(guest_rdi),
                reinterpret_cast<const char*>(guest_rsi),
                static_cast<size_t>(guest_rdx));
        }
        return guest_rdi;
    }
    if (meta.nid == "Q3VBxCXhUHs") {
        // memcpy(void* dst, const void* src, size_t n)
        if (guest_rdi > 0x1000 && guest_rsi > 0x1000 && guest_rdx > 0 && guest_rdx < (1ULL << 28)) {
            std::memcpy(
                reinterpret_cast<void*>(guest_rdi),
                reinterpret_cast<const void*>(guest_rsi),
                static_cast<size_t>(guest_rdx));
        }
        return guest_rdi;
    }
    if (meta.nid == "8zsu04XNsZ4" || meta.nid == "8zTFvBIAIN8" || meta.resolved_name == "memset" || meta.resolved_name == "LibcInternal::memset") {
        // memset(void* dst, int c, size_t n)
        if (guest_rdi > 0x1000 && guest_rdx > 0 && guest_rdx < (1ULL << 28)) {
            std::memset(
                reinterpret_cast<void*>(guest_rdi),
                static_cast<int>(guest_rsi),
                static_cast<size_t>(guest_rdx));
        }
        return guest_rdi;
    }
    if (meta.nid == "1j3S3n-tTW4" || meta.resolved_name == "sceKernelGetTscFrequency") {
        // PS5 Zen 2 CPU TSC frequency: 3.300 GHz (3,300,000,000 Hz)
        return 3300000000ULL;
    }
    if (meta.nid == "vSMAm3cxYTY" || meta.resolved_name == "sceKernelMprotect") {
        return 0; // SCE_OK
    }
    if (meta.nid == "uoUpLGNkygk" || meta.resolved_name == "sceCommonDialogInitialize") {
        return 0; // SCE_OK
    }
    if (meta.nid == "g8cM39EUZ6o" || meta.resolved_name == "sceSysmoduleLoadModule") {
        return 0; // SCE_OK
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
    if (meta.nid == "tsvEmnenz48" || meta.resolved_name == "__cxa_atexit") {
        // __cxa_atexit(func, arg, dso_handle) -> 0 (SCE_OK)
        return 0;
    }
    if (meta.nid == "obuxdTiwkF8") {
        // sceNetCtlGetInfo(code, SceNetCtlInfo* info)
        if (guest_rsi != 0) {
            std::strcpy(reinterpret_cast<char*>(guest_rsi), "YoteiPC");
        }
        return 0;
    }

    // --- P0 Critical Stubs: Return SCE_OK to unblock early boot ---

    // libSceAudioOut2 (18 NIDs) - Audio output
    if (meta.library == "libSceAudioOut2") {
        auto& audio = yotei::audio::AudioOut2HleManager::Instance();
        if (meta.resolved_name == "sceAudioOut2Initialize") {
            return audio.Initialize() ? 0 : -1;
        }
        if (meta.resolved_name == "sceAudioOut2PortCreate") {
            int32_t handle = 0;
            const char* name = reinterpret_cast<const char*>(guest_rdi);
            uint32_t port_type = static_cast<uint32_t>(guest_rsi);
            uint32_t param = static_cast<uint32_t>(guest_rdx);
            int32_t* out_h = reinterpret_cast<int32_t*>(guest_rcx ? guest_rcx : (guest_rdx ? guest_rdx : guest_rsi));
            int32_t rc = audio.PortCreate(name, port_type, param, &handle);
            if (out_h) *out_h = handle;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2UserCreate") {
            int32_t user = 0;
            int32_t* out_u = reinterpret_cast<int32_t*>(guest_rsi ? guest_rsi : guest_rdi);
            int32_t rc = audio.UserCreate(reinterpret_cast<void*>(guest_rdi), &user);
            if (out_u) *out_u = user;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2ContextCreate") {
            int32_t ctx = 0;
            int32_t port_h = static_cast<int32_t>(guest_rdi);
            void* param = reinterpret_cast<void*>(guest_rsi);
            int32_t* out_c = reinterpret_cast<int32_t*>(guest_rdx ? guest_rdx : guest_rcx);
            int32_t rc = audio.ContextCreate(port_h, param, &ctx);
            if (out_c) *out_c = ctx;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2ContextQueryMemory") {
            uint64_t mem_sz = 65536;
            uint64_t* out_sz = reinterpret_cast<uint64_t*>(guest_rsi ? guest_rsi : guest_rdi);
            int32_t rc = audio.ContextQueryMemory(reinterpret_cast<void*>(guest_rdi), &mem_sz);
            if (out_sz) *out_sz = mem_sz;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2ContextGetQueueLevel") {
            uint32_t level = 0;
            int32_t ctx = static_cast<int32_t>(guest_rdi);
            uint32_t* out_lvl = reinterpret_cast<uint32_t*>(guest_rsi);
            int32_t rc = audio.ContextGetQueueLevel(ctx, &level);
            if (out_lvl) *out_lvl = level;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2PortGetState") {
            return audio.PortGetState(static_cast<int32_t>(guest_rdi), reinterpret_cast<void*>(guest_rsi));
        }
        if (meta.resolved_name == "sceAudioOut2PortDestroy" || meta.resolved_name == "sceAudioOut2Close") {
            return audio.PortDestroy(static_cast<int32_t>(guest_rdi));
        }
        if (meta.resolved_name == "sceAudioOut2ContextDestroy") {
            return audio.ContextDestroy(static_cast<int32_t>(guest_rdi));
        }
        if (meta.resolved_name == "sceAudioOut2ContextPush" || meta.resolved_name == "sceAudioOut2Output") {
            int32_t ctx = static_cast<int32_t>(guest_rdi);
            const void* pcm = reinterpret_cast<const void*>(guest_rsi);
            uint32_t count = static_cast<uint32_t>(guest_rdx);
            uint64_t tag = guest_rcx;
            return audio.ContextPush(ctx, pcm, count, tag);
        }
        if (meta.resolved_name == "sceAudioOut2SetVolume") {
            return audio.SetVolume(static_cast<int32_t>(guest_rdi), static_cast<int32_t>(guest_rsi));
        }
        if (meta.resolved_name == "sceAudioOut2GetVolume") {
            int32_t vol = 100;
            int32_t rc = audio.GetVolume(static_cast<int32_t>(guest_rdi), &vol);
            if (guest_rsi != 0) *reinterpret_cast<float*>(guest_rsi) = static_cast<float>(vol) / 100.0f;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2Pause") {
            return audio.Pause(static_cast<int32_t>(guest_rdi));
        }
        if (meta.resolved_name == "sceAudioOut2Resume") {
            return audio.Resume(static_cast<int32_t>(guest_rdi));
        }
        if (meta.resolved_name == "sceAudioOut2Set3DLatency") {
            return audio.Set3DLatency(static_cast<int32_t>(guest_rdi), static_cast<uint32_t>(guest_rsi));
        }
        if (meta.resolved_name == "sceAudioOut2MasteringInit") {
            return audio.MasteringInit(reinterpret_cast<void*>(guest_rdi));
        }
        // Default for any other AudioOut2: SCE_OK
        return 0;
    }

    // libSceAjm (17 NIDs) - Audio Job Manager
    if (meta.library == "libSceAjm") {
        auto& ajm = yotei::audio::AjmHleManager::Instance();
        if (meta.resolved_name == "sceAjmInitialize") {
            return ajm.Initialize(reinterpret_cast<void*>(guest_rdi));
        }
        if (meta.resolved_name == "sceAjmFinalize") {
            return ajm.Finalize();
        }
        if (meta.resolved_name == "sceAjmInstanceCreate") {
            int32_t inst = 0;
            int32_t* out_inst = reinterpret_cast<int32_t*>(guest_rsi ? guest_rsi : guest_rdi);
            int32_t rc = ajm.InstanceCreate(reinterpret_cast<void*>(guest_rdi), &inst);
            if (out_inst) *out_inst = inst;
            return rc;
        }
        if (meta.resolved_name == "sceAjmInstanceDestroy") {
            return ajm.InstanceDestroy(static_cast<int32_t>(guest_rdi));
        }
        if (meta.resolved_name == "sceAjmModuleRegister") {
            return ajm.ModuleRegister(static_cast<int32_t>(guest_rdi), static_cast<uint32_t>(guest_rsi), reinterpret_cast<void*>(guest_rdx));
        }
        if (meta.resolved_name == "sceAjmBatchInitialize") {
            uint64_t bid = 0;
            uint64_t* out_b = reinterpret_cast<uint64_t*>(guest_rdx ? guest_rdx : guest_rsi);
            int32_t rc = ajm.BatchInitialize(static_cast<int32_t>(guest_rdi), reinterpret_cast<void*>(guest_rsi), &bid);
            if (out_b) *out_b = bid;
            return rc;
        }
        if (meta.resolved_name == "sceAjmBatchStart") {
            return ajm.BatchStart(guest_rdi, reinterpret_cast<void*>(guest_rsi));
        }
        if (meta.resolved_name == "sceAjmBatchWait") {
            return ajm.BatchWait(guest_rdi, static_cast<uint32_t>(guest_rsi));
        }
        if (meta.resolved_name == "sceAjmBatchJobGetStatistics") {
            return ajm.BatchJobGetStatistics(guest_rdi, reinterpret_cast<void*>(guest_rsi));
        }
        if (meta.resolved_name == "sceAjmDecAt9ParseConfigData") {
            return ajm.DecAt9ParseConfigData(reinterpret_cast<const void*>(guest_rdi), static_cast<uint32_t>(guest_rsi), reinterpret_cast<void*>(guest_rdx));
        }
        if (meta.resolved_name == "sceAjmBatchErrorDump") {
            return ajm.BatchErrorDump(guest_rdi, reinterpret_cast<void*>(guest_rsi));
        }
        // Default for any other Ajm: SCE_OK
        return 0;
    }

    // libSceSystemService (11 NIDs) - System info queries (language, region, model, firmware)
    if (meta.library == "libSceSystemService") {
        if (meta.resolved_name == "sceSystemServiceGetLanguage") {
            if (guest_rdi != 0) *reinterpret_cast<int32_t*>(guest_rdi) = 1; // Japanese
            return 0;
        }
        if (meta.resolved_name == "sceSystemServiceGetRegion") {
            if (guest_rdi != 0) *reinterpret_cast<int32_t*>(guest_rdi) = 2; // SCE_SYSTEM_SERVICE_REGION_USA
            return 0;
        }
        if (meta.resolved_name == "sceSystemServiceGetModel") {
            if (guest_rdi != 0) *reinterpret_cast<int32_t*>(guest_rdi) = 0x1000; // PS5 standard
            return 0;
        }
        if (meta.resolved_name == "sceSystemServiceGetFirmwareVersion") {
            if (guest_rdi != 0) *reinterpret_cast<uint32_t*>(guest_rdi) = 0x09040001; // 9.04
            return 0;
        }
        if (meta.resolved_name == "sceSystemServiceIsDiscAvailable") {
            if (guest_rdi != 0) *reinterpret_cast<uint8_t*>(guest_rdi) = 0; // no disc
            return 0;
        }
        if (meta.resolved_name == "sceSystemServiceGetEnterButtonAssign") {
            if (guest_rdi != 0) *reinterpret_cast<int32_t*>(guest_rdi) = 1; // Cross = enter (Western)
            return 0;
        }
        if (meta.resolved_name == "sceSystemServiceGetCensorLevel") {
            if (guest_rdi != 0) *reinterpret_cast<int32_t*>(guest_rdi) = 0; // no censor
            return 0;
        }
        // Default for any other SystemService: SCE_OK
        return 0;
    }

    // libSceSaveData_native (14 NIDs) - Save data operations
    if (meta.library == "libSceSaveData_native") {
        if (meta.resolved_name == "sceSaveDataMount") {
            if (guest_rdi != 0) *reinterpret_cast<uint64_t*>(guest_rdi) = 0x100000; // mount_id
            return 0;
        }
        if (meta.resolved_name == "sceSaveDataUmount") return 0;
        if (meta.resolved_name == "sceSaveDataList") {
            if (guest_rsi != 0) {
                // Return empty list
                std::memset(reinterpret_cast<void*>(guest_rsi), 0, 256);
            }
            if (guest_rdx != 0) *reinterpret_cast<uint32_t*>(guest_rdx) = 0; // count
            return 0;
        }
        if (meta.resolved_name == "sceSaveDataRead") return 0;
        if (meta.resolved_name == "sceSaveDataWrite") return 0;
        if (meta.resolved_name == "sceSaveDataDelete") return 0;
        if (meta.resolved_name == "sceSaveDataGetTitleId") {
            if (guest_rsi != 0) std::strcpy(reinterpret_cast<char*>(guest_rsi), "PPSA26344");
            return 0;
        }
        if (meta.resolved_name == "sceSaveDataGetFileSize") {
            if (guest_rsi != 0) *reinterpret_cast<uint64_t*>(guest_rsi) = 0;
            return 0;
        }
        if (meta.resolved_name == "sceSaveDataGetFileSystemSize") {
            if (guest_rsi != 0) *reinterpret_cast<uint64_t*>(guest_rsi) = 1024 * 1024 * 1024; // 1GB
            return 0;
        }
        // Default for any other SaveData: SCE_OK
        return 0;
    }

    // libSceUserService (5 NIDs) - User profiles, login state
    if (meta.library == "libSceUserService") {
        if (meta.resolved_name == "sceUserServiceInitialize") return 0;
        if (meta.resolved_name == "sceUserServiceGetLoginUserIdList") {
            if (guest_rdi > 0x1000) {
                auto* list = reinterpret_cast<int32_t*>(guest_rdi);
                list[0] = 0x10000001; // Primary active user ID
                for (int u = 1; u < 4; ++u) list[u] = -1; // SCE_USER_SERVICE_USER_ID_INVALID
            }
            return 0;
        }
        if (meta.resolved_name == "sceUserServiceGetInitialUser") {
            if (guest_rdi > 0x1000) *reinterpret_cast<int32_t*>(guest_rdi) = 0x10000001;
            return 0;
        }
        if (meta.resolved_name == "sceUserServiceGetProfile") {
            if (guest_rsi > 0x1000) {
                std::strcpy(reinterpret_cast<char*>(guest_rsi), "YoteiPlayer");
            }
            return 0;
        }
        if (meta.resolved_name == "sceUserServiceGetAvatar") {
            if (guest_rsi > 0x1000) *reinterpret_cast<uint32_t*>(guest_rsi) = 0; // no avatar
            return 0;
        }
        if (meta.resolved_name == "sceUserServiceGetUserName") {
            if (guest_rsi > 0x1000) {
                size_t max_len = (guest_rdx > 0 && guest_rdx < 1024) ? static_cast<size_t>(guest_rdx) : 64;
                strncpy_s(reinterpret_cast<char*>(guest_rsi), max_len, "YoteiPlayer", _TRUNCATE);
            }
            return 0;
        }
        // Default for any other UserService: SCE_OK
        return 0;
    }

    // libScePad (11 NIDs) - Interactive Host Gamepad & Input Subsystem
    if (meta.library == "libScePad") {
        uint64_t ret = 0;
        if (yotei::input::PadHleManager::Instance().DispatchNid(
                meta.nid, meta.resolved_name, guest_rdi, guest_rsi, guest_rdx, guest_rcx,
                guest_r8, guest_r9, &ret)) {
            return ret;
        }
        return 0; // SCE_OK default
    }

    // libScePlayGo (9 NIDs) - PlayGo streaming/chunk management
    if (meta.library == "libScePlayGo") {
        if (meta.resolved_name == "scePlayGoInitialize") return 0;
        if (meta.resolved_name == "scePlayGoOpen") {
            if (guest_rdi != 0) *reinterpret_cast<uint32_t*>(guest_rdi) = 1; // handle
            return 0;
        }
        if (meta.resolved_name == "scePlayGoClose") return 0;
        if (meta.resolved_name == "scePlayGoGetChunkId") {
            if (guest_rsi != 0) *reinterpret_cast<uint32_t*>(guest_rsi) = 0;
            return 0;
        }
        if (meta.resolved_name == "scePlayGoGetLocus") {
            if (guest_rsi != 0) *reinterpret_cast<uint64_t*>(guest_rsi) = 0;
            return 0;
        }
        if (meta.resolved_name == "scePlayGoSetToDoList") return 0;
        if (meta.resolved_name == "scePlayGoGetToDoList") {
            if (guest_rsi != 0) *reinterpret_cast<uint32_t*>(guest_rsi) = 0;
            return 0;
        }
        if (meta.resolved_name == "scePlayGoRequest") return 0;
        if (meta.resolved_name == "scePlayGoCancel") return 0;
        // Default for any other PlayGo: SCE_OK
        return 0;
    }

    // libSceAppContent (2 NIDs) - Application content management
    if (meta.library == "libSceAppContent") {
        if (meta.resolved_name == "sceAppContentInitialize") return 0;
        if (meta.resolved_name == "sceAppContentAppParamGetInt") {
            if (guest_rsi != 0) *reinterpret_cast<int32_t*>(guest_rsi) = 0;
            return 0;
        }
        // Default for any other AppContent: SCE_OK
        return 0;
    }

    // libSceNpEntitlementAccess (2 NIDs) - NP entitlement/license checks
    if (meta.library == "libSceNpEntitlementAccess") {
        if (meta.resolved_name == "sceNpEntitlementAccessInitialize") return 0;
        if (meta.resolved_name == "sceNpEntitlementAccessGetEntitlement") {
            if (guest_rsi != 0) *reinterpret_cast<int32_t*>(guest_rsi) = 1; // entitled
            return 0;
        }
        // Default for any other NpEntitlementAccess: SCE_OK
        return 0;
    }

    // libSceOpenPsId (1 NID) - Open PS ID
    if (meta.library == "libSceOpenPsId") {
        if (meta.resolved_name == "sceKernelGetOpenPsId") {
            if (guest_rsi != 0) {
                // Return a dummy OpenPSID (16 bytes)
                std::memset(reinterpret_cast<void*>(guest_rsi), 0, 16);
                *reinterpret_cast<uint64_t*>(guest_rsi) = 0x123456789ABCDEF0ULL;
            }
            return 0;
        }
        // Default for any other OpenPsId: SCE_OK
        return 0;
    }

    // --- libc File I/O Stubs (using host stdio) ---
    static std::mutex g_file_mutex;
    static std::unordered_map<uint64_t, FILE*> g_file_map;
    static std::unordered_map<uint64_t, int> g_file_refcount;
    static uint64_t g_next_file_handle = 0x1000;
    static const size_t MAX_OPEN_FILES = 1024;

    if (meta.library == "libc") {
        // fopen(const char* path, const char* mode) -> FILE*
        if (meta.resolved_name == "fopen") {
            if (guest_rdi != 0 && guest_rsi != 0) {
                const char* path = reinterpret_cast<const char*>(guest_rdi);
                const char* mode = reinterpret_cast<const char*>(guest_rsi);
                // Redirect to our VFS if path starts with /app0 or /cache_ps5
                auto& vfs_ref = kernel::VirtualFileSystem::Instance();
                auto host_path = vfs_ref.ResolveGuestPath(path);
                if (!host_path.empty()) {
                    // Convert wchar_t path to char for fopen
                    std::string host_path_str = host_path.string();
                    FILE* f = std::fopen(host_path_str.c_str(), mode);
                    if (f) {
                        std::lock_guard<std::mutex> lock(g_file_mutex);
                        if (g_file_map.size() >= MAX_OPEN_FILES) {
                            std::fclose(f);
                            return 0; // Too many open files
                        }
                        uint64_t handle = ++g_next_file_handle;
                        g_file_map[handle] = f;
                        g_file_refcount[handle] = 1;
                        return handle;
                    }
                }
                // Fallback: try host path directly
                FILE* f = std::fopen(path, mode);
                if (f) {
                    std::lock_guard<std::mutex> lock(g_file_mutex);
                    if (g_file_map.size() >= MAX_OPEN_FILES) {
                        std::fclose(f);
                        return 0;
                    }
                    uint64_t handle = ++g_next_file_handle;
                    g_file_map[handle] = f;
                    g_file_refcount[handle] = 1;
                    return handle;
                }
            }
            return 0; // NULL
        }

        // fclose(FILE* stream) -> int
        if (meta.resolved_name == "fclose") {
            if (guest_rdi != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rdi);
                if (it != g_file_map.end()) {
                    // Reference counting to prevent double-free
                    auto it_ref = g_file_refcount.find(guest_rdi);
                    if (it_ref != g_file_refcount.end()) {
                        if (--it_ref->second > 0) {
                            return 0; // Still has references
                        }
                        g_file_refcount.erase(it_ref);
                    }
                    std::fclose(it->second);
                    g_file_map.erase(it);
                    return 0;
                }
            }
            return -1; // EOF
        }

        // fread(void* ptr, size_t size, size_t nmemb, FILE* stream) -> size_t
        if (meta.resolved_name == "fread") {
            if (guest_rdi != 0 && guest_rsi > 0 && guest_rdx > 0 && guest_rcx != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rcx);
                if (it != g_file_map.end()) {
                    size_t read = std::fread(
                        reinterpret_cast<void*>(guest_rdi),
                        static_cast<size_t>(guest_rsi),
                        static_cast<size_t>(guest_rdx),
                        it->second);
                    return read;
                }
            }
            return 0;
        }

        // fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) -> size_t
        if (meta.resolved_name == "fwrite") {
            if (guest_rdi != 0 && guest_rsi > 0 && guest_rdx > 0 && guest_rcx != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rcx);
                if (it != g_file_map.end()) {
                    size_t written = std::fwrite(
                        reinterpret_cast<const void*>(guest_rdi),
                        static_cast<size_t>(guest_rsi),
                        static_cast<size_t>(guest_rdx),
                        it->second);
                    return written;
                }
            }
            return 0;
        }

        // fseek(FILE* stream, long offset, int whence) -> int
        if (meta.resolved_name == "fseek") {
            if (guest_rdi != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rdi);
                if (it != g_file_map.end()) {
                    int result = std::fseek(it->second, static_cast<long>(guest_rsi), static_cast<int>(guest_rdx));
                    return result;
                }
            }
            return -1;
        }

        // ftell(FILE* stream) -> long
        if (meta.resolved_name == "ftell") {
            if (guest_rdi != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rdi);
                if (it != g_file_map.end()) {
                    long pos = std::ftell(it->second);
                    return static_cast<uint64_t>(pos);
                }
            }
            return -1;
        }

        // feof(FILE* stream) -> int
        if (meta.resolved_name == "feof") {
            if (guest_rdi != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rdi);
                if (it != g_file_map.end()) {
                    return std::feof(it->second) ? 1 : 0;
                }
            }
            return 0;
        }

        // ferror(FILE* stream) -> int
        if (meta.resolved_name == "ferror") {
            if (guest_rdi != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rdi);
                if (it != g_file_map.end()) {
                    return std::ferror(it->second) ? 1 : 0;
                }
            }
            return 0;
        }

        // rewind(FILE* stream)
        if (meta.resolved_name == "rewind") {
            if (guest_rdi != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rdi);
                if (it != g_file_map.end()) {
                    std::rewind(it->second);
                }
            }
            return 0;
        }

        // setvbuf(FILE* stream, char* buf, int mode, size_t size) -> int
        if (meta.resolved_name == "setvbuf") {
            if (guest_rdi != 0) {
                std::lock_guard<std::mutex> lock(g_file_mutex);
                auto it = g_file_map.find(guest_rdi);
                if (it != g_file_map.end()) {
                    return std::setvbuf(it->second,
                                        reinterpret_cast<char*>(guest_rsi),
                                        static_cast<int>(guest_rdx),
                                        static_cast<size_t>(guest_rcx));
                }
            }
            return -1;
        }
    }

    // --- Generic Stub Sink: Return SCE_OK for all other unhandled NIDs ---
    // This lets the game continue instead of hitting unhandled stub warnings
    // Only log once per unique NID to avoid spam
    {
        static std::mutex stub_sink_mutex;
        static std::unordered_set<std::string> warned_nids;
        std::lock_guard<std::mutex> lock(stub_sink_mutex);
        if (warned_nids.insert(meta.nid).second) {
            // Only log for non-core libraries to reduce noise, or if verbose mode
            bool should_log = g_verbose_unhandled || (meta.library != "libc" && meta.library != "libkernel");
            if (should_log) {
                std::cout << "  [STUB SINK] " << meta.library << "::" << meta.resolved_name
                          << " (" << meta.nid << ") -> returning SCE_OK\n" << std::flush;
            }
        }
    }
    return 0; // SCE_OK
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
        // and preserving RBX, R12, R13, R14, R15 (SysV callee-saved) across HleDispatchTrampoline
        uint8_t* stub = slab + slot_idx * 96;
        uint8_t code[] = {
            0x55,                                     // push rbp
            0x48, 0x89, 0xE5,                         // mov rbp, rsp
            0x41, 0x57,                               // push r15
            0x41, 0x56,                               // push r14
            0x41, 0x55,                               // push r13
            0x41, 0x54,                               // push r12
            0x57,                                     // push rdi
            0x56,                                     // push rsi
            0x53,                                     // push rbx
            0x48, 0x83, 0xE4, 0xF0,                   // and rsp, -16
            0x48, 0x83, 0xEC, 0x40,                   // sub rsp, 64
            0x48, 0x89, 0x4C, 0x24, 0x20,             // mov [rsp+0x20], rcx
            0x4C, 0x89, 0x44, 0x24, 0x28,             // mov [rsp+0x28], r8
            0x4C, 0x89, 0x4C, 0x24, 0x30,             // mov [rsp+0x30], r9
            0x49, 0x89, 0xD1,                         // mov r9, rdx
            0x49, 0x89, 0xF0,                         // mov r8, rsi
            0x48, 0x89, 0xFA,                         // mov rdx, rdi
            0xB9, 0x00, 0x00, 0x00, 0x00,             // mov ecx, slot_idx   (offset 48)
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,       // movabs rax, &HleDispatchTrampoline (offset 54)
            0xFF, 0xD0,                               // call rax
            0x48, 0x8D, 0x65, 0xC8,                   // lea rsp, [rbp - 56] (7 pushes * 8 = 56)
            0x5B,                                     // pop rbx
            0x5E,                                     // pop rsi
            0x5F,                                     // pop rdi
            0x41, 0x5C,                               // pop r12
            0x41, 0x5D,                               // pop r13
            0x41, 0x5E,                               // pop r14
            0x41, 0x5F,                               // pop r15
            0x5D,                                     // pop rbp
            0xC3                                      // ret
        };
        std::memcpy(code + 48, &slot_idx, sizeof(uint32_t));
        uint64_t fn_addr = reinterpret_cast<uint64_t>(&HleDispatchTrampoline);
        std::memcpy(code + 54, &fn_addr, sizeof(uint64_t));
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

void NidRegistry::PrintUnhandledStubSummary() {
    std::lock_guard<std::mutex> lock(g_unhandled_mutex);
    if (g_unhandled_stubs.empty()) {
        std::cout << "[+] All invoked HLE stubs were handled (0 unhandled stubs)!\n";
        return;
    }
    std::cout << "\n=================================================================\n";
    std::cout << " UNHANDLED STUB CALL REPORT (" << g_unhandled_stubs.size() << " unique stubs invoked)\n";
    std::cout << "=================================================================\n";
    for (const auto& [nid, rec] : g_unhandled_stubs) {
        std::cout << "  [" << std::setw(16) << std::left << rec.library << "] "
                  << std::setw(36) << rec.resolved_name
                  << " (" << rec.nid << ") -> called " << rec.call_count << " times (last rdi=0x"
                  << std::hex << rec.last_rdi << std::dec << ")\n";
    }
    std::cout << "=================================================================\n" << std::flush;
}

size_t NidRegistry::GetUnhandledStubCount() {
    std::lock_guard<std::mutex> lock(g_unhandled_mutex);
    return g_unhandled_stubs.size();
}

void NidRegistry::SetVerboseUnhandled(bool enabled) {
    g_verbose_unhandled = enabled;
}

} // namespace yotei::hle
