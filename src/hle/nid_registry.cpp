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
#include <atomic>
#include <chrono>
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
#include <immintrin.h>
#endif

namespace yotei::hle {

namespace {

struct BoundSlotMeta {
    std::string library;
    std::string nid;
    std::string resolved_name;
    uint64_t got_vaddr;
    uint64_t call_count = 0;
};

std::vector<BoundSlotMeta> g_bound_slots;
uint64_t g_guest_base = 0;
std::atomic<size_t> g_call_counter{0};
uint64_t g_stack_canary_value = 0x594f54454943414eULL; // "YOTEICAN"
uint64_t g_need_flag_value = 1;
uint64_t g_dummy_iob_object[16] = {0};

std::mutex g_unhandled_mutex;
std::unordered_map<std::string, UnhandledStubRecord> g_unhandled_stubs;
std::mutex g_telemetry_mutex;
bool g_verbose_unhandled = false;

struct GameMainCallRecord {
    size_t global_seq = 0;
    uint64_t slot_index = 0;
    std::string library;
    std::string resolved_name;
    std::string nid;
    uint64_t rdi = 0;
    uint64_t rsi = 0;
    uint64_t rdx = 0;
    uint64_t repeat_count = 1;
};

std::atomic<uint32_t> g_game_main_host_tid{0};
std::vector<GameMainCallRecord> g_main_thread_timeline;

static uint64_t HleDispatchInner(
    uint64_t slot_index,
    uint64_t guest_rdi,
    uint64_t guest_rsi,
    uint64_t guest_rdx,
    uint64_t guest_rcx,
    uint64_t guest_r8,
    uint64_t guest_r9,
    uint64_t guest_stack_arg0);

// SysV AMD64 ABI passes args in: RDI, RSI, RDX, RCX, R8, R9.
// Our generated 96-byte x86-64 trampoline translates a SysV call into MS x64 call:
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
    uint64_t guest_r9,
    uint64_t guest_stack_arg0) {
#ifdef _WIN32
    __try {
        return HleDispatchInner(
            slot_index, guest_rdi, guest_rsi, guest_rdx,
            guest_rcx, guest_r8, guest_r9, guest_stack_arg0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (slot_index < g_bound_slots.size()) {
            const auto& meta = g_bound_slots[slot_index];
            std::cout << "  [HLE SEH GUARD] Fault inside " << meta.library << "::" << meta.resolved_name
                      << " (" << meta.nid << ") rdi=0x" << std::hex << guest_rdi
                      << " rsi=0x" << guest_rsi << " rdx=0x" << guest_rdx << std::dec << " -> returning 0\n" << std::flush;
        }
        return 0;
    }
#else
    return HleDispatchInner(
        slot_index, guest_rdi, guest_rsi, guest_rdx,
        guest_rcx, guest_r8, guest_r9, guest_stack_arg0);
#endif
}

static uint64_t HleDispatchInner(
    uint64_t slot_index,
    uint64_t guest_rdi,
    uint64_t guest_rsi,
    uint64_t guest_rdx,
    uint64_t guest_rcx,
    uint64_t guest_r8,
    uint64_t guest_r9,
    uint64_t guest_stack_arg0) {
    if (slot_index >= g_bound_slots.size()) return 0;
    auto& meta = g_bound_slots[slot_index];
    size_t cur_call = ++g_call_counter;
    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&meta.call_count));

#ifdef _WIN32
    uint32_t target_tid = g_game_main_host_tid.load(std::memory_order_relaxed);
    if (target_tid != 0 && ::GetCurrentThreadId() == target_tid) {
        // Fast path for single-threaded game_main timeline tracking
        if (!g_main_thread_timeline.empty() &&
            g_main_thread_timeline.back().slot_index == slot_index) {
            auto& back = g_main_thread_timeline.back();
            back.repeat_count++;
            back.rdi = guest_rdi;
            back.rsi = guest_rsi;
            back.rdx = guest_rdx;
        } else if (g_main_thread_timeline.size() >= 2 &&
                   g_main_thread_timeline[g_main_thread_timeline.size() - 2].slot_index == slot_index) {
            auto& prev2 = g_main_thread_timeline[g_main_thread_timeline.size() - 2];
            prev2.repeat_count++;
            prev2.rdi = guest_rdi;
            prev2.rsi = guest_rsi;
            prev2.rdx = guest_rdx;
        } else {
            std::lock_guard<std::mutex> tlock(g_telemetry_mutex);
            std::string disp_name = meta.resolved_name;
            if (meta.resolved_name == "fopen" && guest_rdi > 0x10000ULL) {
                disp_name += "('" + std::string(reinterpret_cast<const char*>(guest_rdi)) + "')";
            }
            if (g_main_thread_timeline.size() >= 256) {
                g_main_thread_timeline.erase(g_main_thread_timeline.begin());
            }
            g_main_thread_timeline.push_back({
                cur_call, slot_index, meta.library, disp_name, meta.nid,
                guest_rdi, guest_rsi, guest_rdx, 1
            });
        }
    }
#endif

    if (cur_call <= 120) {
        std::cout << "  [HLE #" << std::setw(2) << cur_call << "] "
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
            guest_rdi, guest_rsi, guest_rdx, guest_rcx, guest_r8, guest_r9, &sub_ret, guest_stack_arg0)) {
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
        int32_t fd = vfs.Open(
            reinterpret_cast<const char*>(guest_rdi),
            static_cast<int32_t>(guest_rsi),
            static_cast<int32_t>(guest_rdx));
        return static_cast<uint64_t>(fd);
    }
    if (meta.nid == "Cg4srZ6TKbU" || meta.resolved_name == "sceKernelRead" || meta.resolved_name == "FileSystem::KernelRead" || meta.resolved_name == "read") {
        if (guest_rsi < 0x1000) return static_cast<uint64_t>(-14);
        return static_cast<uint64_t>(vfs.Read(
            static_cast<int32_t>(guest_rdi),
            reinterpret_cast<void*>(guest_rsi),
            guest_rdx));
    }
    if (meta.nid == "4wSze92BhLI" || meta.resolved_name == "sceKernelWrite" || meta.resolved_name == "write") {
        if (guest_rsi < 0x1000) return static_cast<uint64_t>(-14);
        return static_cast<uint64_t>(vfs.Write(
            static_cast<int32_t>(guest_rdi),
            reinterpret_cast<const void*>(guest_rsi),
            guest_rdx));
    }
    if (meta.nid == "oib76F-12fk" || meta.resolved_name == "sceKernelLseek" || meta.resolved_name == "lseek") {
        return static_cast<uint64_t>(vfs.Lseek(
            static_cast<int32_t>(guest_rdi),
            static_cast<int64_t>(guest_rsi),
            static_cast<int32_t>(guest_rdx)));
    }
    if (meta.nid == "j2AIqSqJP0w" || meta.resolved_name == "sceKernelGetdents") {
        std::cout << "  [VFS] sceKernelGetdents(fd=" << std::dec << static_cast<int32_t>(guest_rdi)
                  << ", buf=0x" << std::hex << guest_rsi << ", count=" << std::dec << guest_rdx << ")\n" << std::flush;
        return 0; // EOF / 0 directory entries remaining
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
    if (meta.nid == "-2IRUCO--PM" || meta.resolved_name == "sceKernelReadTsc") {
        // Monotonic 64-bit Zen 2 TSC counter scaled to 3.300 GHz (3300 ticks per microsecond)
        static const auto s_boot_tp = std::chrono::steady_clock::now();
        auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - s_boot_tp).count();
        return static_cast<uint64_t>((elapsed_ns * 33ULL) / 10ULL) + 0x100000000ULL;
    }
    if (meta.nid == "4J2sUJmuHZQ" || meta.resolved_name == "sceKernelGetProcessTime") {
        // Elapsed process time in microseconds
        static const auto s_boot_tp = std::chrono::steady_clock::now();
        auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - s_boot_tp).count();
        return static_cast<uint64_t>(elapsed_us) + 1000ULL;
    }
    if (meta.nid == "ejekcaNQNq0" || meta.resolved_name == "sceKernelGettimeofday") {
        // sceKernelGettimeofday(SceKernelTimeval* tp)
        if (guest_rdi >= 0x1000) {
            auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto* tv = reinterpret_cast<int64_t*>(guest_rdi);
            tv[0] = now_us / 1000000LL;
            tv[1] = now_us % 1000000LL;
        }
        return 0; // SCE_OK
    }
    if (meta.library == "libSceRtc" ||
        meta.nid == "18B2NS1y9UU" || meta.nid == "zO9UL3qIINQ" || meta.nid == "M1TvFst-jrM") {
        // sceRtcGetCurrentTick(rdi=out_tick) / sceRtcGetCurrentNetworkTick(rdi=out_tick)
        // sceRtcConvertUtcToLocalTime(const SceRtcTick* pUtc=rdi, SceRtcTick* pLocal=rsi)
        auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        uint64_t ps5_rtc_tick = 62135596800000000ULL + static_cast<uint64_t>(now_us);
        if (meta.nid == "M1TvFst-jrM") {
            uint64_t utc_val = (guest_rdi >= 0x1000) ? *reinterpret_cast<const uint64_t*>(guest_rdi) : ps5_rtc_tick;
            if (guest_rsi >= 0x1000) {
                *reinterpret_cast<uint64_t*>(guest_rsi) = utc_val;
            }
        } else if (guest_rdi >= 0x1000) {
            *reinterpret_cast<uint64_t*>(guest_rdi) = ps5_rtc_tick;
        }
        return 0; // SCE_OK
    }
    if (meta.nid == "rVjRvHJ0X6c" || meta.resolved_name == "sceKernelVirtualQuery") {
        // sceKernelVirtualQuery(const void* addr, int flags, SceKernelVirtualQueryInfo* info, size_t infoSize)
        if (guest_rdx >= 0x1000 && guest_rcx >= 32) {
            std::memset(reinterpret_cast<void*>(guest_rdx), 0, static_cast<size_t>(guest_rcx));
            uint64_t page_base = guest_rdi & ~0x3FFFULL;
            auto* info_u64 = reinterpret_cast<uint64_t*>(guest_rdx);
            info_u64[0] = page_base;                // start
            info_u64[1] = page_base + 0x200000ULL;  // end
            info_u64[2] = 0;                        // offset
            auto* info_u32 = reinterpret_cast<uint32_t*>(guest_rdx + 24);
            info_u32[0] = 0x33;                     // protection (CPU RW + GPU RW)
        }
        return 0; // SCE_OK
    }
    // Kernel Async Disk I/O (sceKernelAio*) - Milestone 20
    if (meta.nid == "vYU8P9Td2Zo" || meta.nid == "nu4a0-arQis" ||
        meta.resolved_name == "sceKernelAioInitializeImpl" ||
        meta.resolved_name == "sceKernelAioInitializeParam") {
        return 0; // SCE_OK
    }
    if (meta.nid == "HgX7+AORI58" || meta.nid == "XQ8C8y+de+E" ||
        meta.resolved_name == "sceKernelAioSubmitReadCommands" ||
        meta.resolved_name == "sceKernelAioSubmitWriteCommands") {
        // sceKernelAioSubmitReadCommands(SceKernelAioRWRequest reqs[], uint32_t count, int32_t prio, int32_t ids[])
        static std::atomic<int32_t> s_next_aio_id{1};
        uint32_t count = (guest_rsi > 0 && guest_rsi <= 1024) ? static_cast<uint32_t>(guest_rsi) : 0;
        if (guest_rcx >= 0x1000) {
            auto* out_ids = reinterpret_cast<int32_t*>(guest_rcx);
            for (uint32_t i = 0; i < count; ++i) {
                out_ids[i] = s_next_aio_id.fetch_add(1, std::memory_order_relaxed);
            }
        }
        return 0; // SCE_OK
    }
    if (meta.nid == "2pOuoWoCxdk" || meta.nid == "KOF-oJbQVvc" || meta.nid == "5TgME6AYty4" ||
        meta.resolved_name == "sceKernelAioPollRequest" ||
        meta.resolved_name == "sceKernelAioWaitRequest" ||
        meta.resolved_name == "sceKernelAioDeleteRequest") {
        // sceKernelAioWaitRequest / PollRequest(int32_t ids[], uint32_t count, int32_t states[], uint32_t* usec)
        uint32_t count = (guest_rsi > 0 && guest_rsi <= 1024) ? static_cast<uint32_t>(guest_rsi) : 0;
        if (guest_rdx >= 0x1000) {
            auto* out_states = reinterpret_cast<int32_t*>(guest_rdx);
            for (uint32_t i = 0; i < count; ++i) {
                out_states[i] = 0; // SCE_OK / Completed
            }
        }
        return 0; // SCE_OK
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
    if (meta.nid == "uMei1W9uyNo" || meta.resolved_name == "exit") {
        std::cout << "  [HLE EXIT] Guest called exit(" << static_cast<int32_t>(guest_rdi)
                  << ") at Global #" << cur_call << " (RSI=0x" << std::hex << guest_rsi
                  << " RDX=0x" << guest_rdx << ")\n";
        // Inspect "all_shaders" package at [0x806d8a6d8 + 0x540] and request at [0x806d8a6d8 + 0x548]
        uint64_t pkg_ptr = *reinterpret_cast<uint64_t*>(0x806d8a6d8ULL + 0x540);
        uint64_t req_ptr = *reinterpret_cast<uint64_t*>(0x806d8a6d8ULL + 0x548);
        uint64_t pg_arr  = *reinterpret_cast<uint64_t*>(0x806b6dd70ULL);
        int32_t  pg_cnt  = *reinterpret_cast<int32_t*>(0x806b6dd78ULL);
        std::cout << "    [AllShaders] pkg_ptr=0x" << pkg_ptr << " req_ptr=0x" << req_ptr
                  << " [0x806b6dd88]=0x" << *reinterpret_cast<uint64_t*>(0x806b6dd88ULL)
                  << " pg_arr=0x" << pg_arr << " pg_cnt=" << std::dec << pg_cnt << std::hex << "\n";
        if (pg_arr > 0x10000000ULL && pg_cnt > 0 && pg_cnt < 64) {
            for (int32_t c = 0; c < pg_cnt; ++c) {
                uint64_t e = pg_arr + c * 40;
                std::cout << "      [Chunk " << std::dec << c << std::hex << "] +19=" << (int)*reinterpret_cast<uint8_t*>(e + 0x19)
                          << " +20=" << (int)*reinterpret_cast<uint8_t*>(e + 0x20)
                          << " +21=" << (int)*reinterpret_cast<uint8_t*>(e + 0x21)
                          << " +22=" << (int)*reinterpret_cast<uint8_t*>(e + 0x22) << "\n";
            }
        }
        if (pkg_ptr > 0x10000000ULL) {
            uint64_t file_ptr = *reinterpret_cast<uint64_t*>(pkg_ptr + 0xa8);
            std::cout << "    [Pkg 0x" << pkg_ptr << "] +70(type)=0x" << (int)*reinterpret_cast<uint8_t*>(pkg_ptr + 0x70)
                      << " +71(hi_state)=0x" << (int)*reinterpret_cast<uint8_t*>(pkg_ptr + 0x71)
                      << " +88(lo_state)=0x" << *reinterpret_cast<uint32_t*>(pkg_ptr + 0x88)
                      << " +90(err)=0x" << *reinterpret_cast<uint32_t*>(pkg_ptr + 0x90)
                      << " +a0(active_req)=0x" << *reinterpret_cast<uint64_t*>(pkg_ptr + 0xa0)
                      << " +a8(file)=0x" << file_ptr << "\n";
            if (file_ptr > 0x10000000ULL) {
                std::cout << "    [File 0x" << file_ptr << "] +78(size)=0x" << *reinterpret_cast<uint64_t*>(file_ptr + 0x78)
                          << " +f8=0x" << *reinterpret_cast<uint32_t*>(file_ptr + 0xf8)
                          << " +fc(status)=0x" << *reinterpret_cast<uint32_t*>(file_ptr + 0xfc)
                          << " +100(fd)=0x" << *reinterpret_cast<uint32_t*>(file_ptr + 0x100)
                          << " +104(apr_id)=0x" << *reinterpret_cast<uint32_t*>(file_ptr + 0x104)
                          << " +114(state)=0x" << *reinterpret_cast<uint32_t*>(file_ptr + 0x114) << "\n";
            }
        }
        if (req_ptr > 0x10000000ULL) {
            std::cout << "    [Req 0x" << req_ptr << "] +6c=0x" << *reinterpret_cast<uint32_t*>(req_ptr + 0x6c)
                      << " +70=0x" << *reinterpret_cast<uint32_t*>(req_ptr + 0x70)
                      << " +74(err)=0x" << *reinterpret_cast<uint32_t*>(req_ptr + 0x74)
                      << " +78=0x" << (int)*reinterpret_cast<uint8_t*>(req_ptr + 0x78) << "\n";
        }
        uint64_t pkg_mgr = 0x80549d6a0ULL;
        uint64_t req_arr = *reinterpret_cast<uint64_t*>(pkg_mgr + 0xa8);
        int32_t  req_cnt = *reinterpret_cast<int32_t*>(pkg_mgr + 0xb0);
        int32_t  act_cnt = *reinterpret_cast<int32_t*>(pkg_mgr + 0xc0);
        std::cout << "    [PkgMgr 0x80549d6a0] req_arr=0x" << req_arr
                  << " req_cnt=" << std::dec << req_cnt << " act_cnt=" << act_cnt << std::hex << "\n";
        // Also inspect FileManager [0x804ddeb38]
        uint64_t fm = 0x804ddeb38ULL;
        std::cout << "    [FileMgr 0x804ddeb38] +2bc(q0_tid)=0x" << *reinterpret_cast<uint32_t*>(fm + 0x2b4)
                  << " +2c0=0x" << *reinterpret_cast<uint32_t*>(fm + 0x2b8)
                  << " +2c4=0x" << *reinterpret_cast<uint32_t*>(fm + 0x2bc)
                  << " free_files=0x" << *reinterpret_cast<uint64_t*>(fm + 0x148)
                  << " files_per_slab=0x" << *reinterpret_cast<uint32_t*>(fm + 0x120)
                  << " paths_per_slab=0x" << *reinterpret_cast<uint32_t*>(0x804ddebe8ULL)
                  << std::dec << "\n" << std::flush;
        while (true) {
            Sleep(1000);
        }
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
        auto is_valid_out_ptr = [](uint64_t p) -> bool {
#ifdef _WIN32
            if (p < 0x100000ULL) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi)) == 0) return false;
            return (mbi.State == MEM_COMMIT) &&
                   (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
#else
            return p >= 0x100000ULL;
#endif
        };
        if (meta.resolved_name == "sceAudioOut2Initialize") {
            return audio.Initialize() ? 0 : -1;
        }
        if (meta.resolved_name == "sceAudioOut2PortCreate") {
            int32_t handle = 1;
            const char* name = is_valid_out_ptr(guest_rdi) ? reinterpret_cast<const char*>(guest_rdi) : "AudioPort";
            uint32_t port_type = static_cast<uint32_t>(guest_rsi);
            uint32_t param = static_cast<uint32_t>(guest_rdx);
            int32_t rc = audio.PortCreate(name, port_type, param, &handle);
            uint64_t out_addr = is_valid_out_ptr(guest_rcx) ? guest_rcx
                              : (is_valid_out_ptr(guest_rdx) ? guest_rdx
                              : (is_valid_out_ptr(guest_rsi) ? guest_rsi : 0));
            if (out_addr) *reinterpret_cast<int32_t*>(out_addr) = handle;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2UserCreate") {
            int32_t user = 1;
            int32_t rc = audio.UserCreate(reinterpret_cast<void*>(guest_rdi), &user);
            uint64_t out_addr = is_valid_out_ptr(guest_rsi) ? guest_rsi : (is_valid_out_ptr(guest_rdi) ? guest_rdi : 0);
            if (out_addr) *reinterpret_cast<int32_t*>(out_addr) = user;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2ContextCreate") {
            int32_t ctx = 1;
            int32_t port_h = static_cast<int32_t>(guest_rdi);
            void* param = reinterpret_cast<void*>(guest_rsi);
            int32_t rc = audio.ContextCreate(port_h, param, &ctx);
            uint64_t out_addr = is_valid_out_ptr(guest_rdx) ? guest_rdx
                              : (is_valid_out_ptr(guest_rcx) ? guest_rcx
                              : (is_valid_out_ptr(guest_rdi) ? guest_rdi : 0));
            if (out_addr) *reinterpret_cast<int32_t*>(out_addr) = ctx;
            return rc;
        }
        if (meta.resolved_name == "sceAudioOut2ContextQueryMemory") {
            uint64_t mem_sz = 65536;
            int32_t rc = audio.ContextQueryMemory(reinterpret_cast<void*>(guest_rdi), &mem_sz);
            uint64_t out_addr = is_valid_out_ptr(guest_rsi) ? guest_rsi : (is_valid_out_ptr(guest_rdi) ? guest_rdi : 0);
            if (out_addr) *reinterpret_cast<uint64_t*>(out_addr) = mem_sz;
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
        if (meta.nid == "yH17Q6NWtVg" || meta.resolved_name == "sceUserServiceGetEvent") {
            // Return first login event once, then SCE_USER_SERVICE_ERROR_NO_EVENT (0x80960004)
            static std::atomic<bool> s_login_event_sent{false};
            if (!s_login_event_sent.exchange(true) && guest_rdi > 0x1000) {
                auto* ev = reinterpret_cast<int32_t*>(guest_rdi);
                ev[0] = 0;          // SCE_USER_SERVICE_EVENT_TYPE_LOGIN
                ev[1] = 0x10000001; // Primary active user ID
                return 0;           // SCE_OK
            }
            return 0x80960004U; // SCE_USER_SERVICE_ERROR_NO_EVENT
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

    // libScePlayGo (9+ NIDs) - PlayGo streaming/chunk management
    if (meta.library == "libScePlayGo" || meta.library == "libScePlayGoDialog") {
        if (meta.resolved_name == "scePlayGoInitialize") return 0;
        if (meta.resolved_name == "scePlayGoOpen") {
            if (guest_rdi > 0x1000) *reinterpret_cast<uint32_t*>(guest_rdi) = 1; // handle
            return 0;
        }
        if (meta.resolved_name == "scePlayGoClose") return 0;
        if (meta.resolved_name == "scePlayGoGetChunkId") {
            // scePlayGoGetChunkId(handle=edi, uint16_t* outChunkIds=rsi, uint32_t maxEntries=edx, uint32_t* outEntries=rcx)
            uint32_t max_entries = static_cast<uint32_t>(guest_rdx);
            uint32_t count = (max_entries < 64) ? max_entries : 64;
            if (guest_rsi > 0x1000 && count > 0) {
                auto* ids = reinterpret_cast<uint16_t*>(guest_rsi);
                for (uint32_t i = 0; i < count; ++i) {
                    ids[i] = static_cast<uint16_t>(i);
                }
            }
            if (guest_rcx > 0x1000) {
                *reinterpret_cast<uint32_t*>(guest_rcx) = count;
            }
            return 0;
        }
        if (meta.resolved_name == "scePlayGoGetLocus") {
            // scePlayGoGetLocus(handle=edi, const uint16_t* chunkIds=rsi, uint32_t count=edx, uint8_t* outLoci=rcx)
            uint32_t count = static_cast<uint32_t>(guest_rdx);
            if (guest_rcx > 0x1000 && count > 0 && count < 4096) {
                // 3 = SCE_PLAYGO_LOCUS_LOCAL_FAST (fully installed on local SSD)
                std::memset(reinterpret_cast<void*>(guest_rcx), 3, count);
            }
            return 0;
        }
        if (meta.resolved_name == "scePlayGoSetToDoList") return 0;
        if (meta.resolved_name == "scePlayGoGetToDoList") {
            // scePlayGoGetToDoList(handle=edi, outTodoList=rsi, uint32_t maxEntries=edx, uint32_t* outEntries=rcx)
            if (guest_rcx > 0x1000) *reinterpret_cast<uint32_t*>(guest_rcx) = 0;
            return 0;
        }
        if (meta.resolved_name == "scePlayGoGetProgress") {
            // scePlayGoGetProgress(handle=edi, const uint16_t* chunkIds=rsi, uint32_t count=edx, ScePlayGoProgress* outProgress=rcx)
            if (guest_rcx > 0x1000) {
                auto* prog = reinterpret_cast<uint64_t*>(guest_rcx);
                prog[0] = 0x100000ULL; // progressSize
                prog[1] = 0x100000ULL; // totalSize
            }
            return 0;
        }
        if (meta.resolved_name == "scePlayGoGetEta") {
            if (guest_rcx > 0x1000) *reinterpret_cast<uint64_t*>(guest_rcx) = 0;
            return 0;
        }
        if (meta.resolved_name == "scePlayGoRequest") return 0;
        if (meta.resolved_name == "scePlayGoCancel") return 0;
        // Default for any other PlayGo / PlayGoDialog: SCE_OK
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

    // libSceNpUniversalDataSystem & libSceNpTrophy2 (Milestone 23: Handle/Context Creation & Worker Polling Yield)
    if (meta.library == "libSceNpUniversalDataSystem" || meta.library == "libSceNpTrophy2") {
        if (meta.resolved_name.find("CreateHandle") != std::string::npos ||
            meta.resolved_name.find("CreateContext") != std::string::npos) {
            if (guest_rdi > 0x1000) {
                *reinterpret_cast<uint32_t*>(guest_rdi) = 1;
            }
            return 0;
        }
        if (meta.nid == "tpFJ8LIKvPw" || meta.nid == "y3zHpdZO6ME") {
            // Worker_23 / Worker_24 background sync calls: yield quantum to prevent tight spin
            Sleep(1);
        }
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

        // Core C string, memory & formatting primitives (SysV va_list vsnprintf, snprintf, strcmp, strncmp, strcpy, memcmp, memmove, strchr, strrchr, strstr)
        if (meta.nid == "Q2V+iqvjgC0" || meta.resolved_name == "vsnprintf") {
            // vsnprintf(char* dst=rdi, size_t size=rsi, const char* fmt=rdx, SysV_va_list* ap=rcx)
            if (guest_rdx <= 0x1000 || guest_rcx <= 0x1000) return 0;
            struct SysVVaList {
                uint32_t gp_offset;
                uint32_t fp_offset;
                uint8_t* overflow_arg_area;
                uint8_t* reg_save_area;
            };
            SysVVaList va = *reinterpret_cast<const SysVVaList*>(guest_rcx);
            auto next_gp = [&]() -> uint64_t {
                if (va.gp_offset <= 40 && reinterpret_cast<uintptr_t>(va.reg_save_area) > 0x1000) {
                    uint64_t v = *reinterpret_cast<const uint64_t*>(va.reg_save_area + va.gp_offset);
                    va.gp_offset += 8;
                    return v;
                }
                if (reinterpret_cast<uintptr_t>(va.overflow_arg_area) > 0x1000) {
                    uint64_t v = *reinterpret_cast<const uint64_t*>(va.overflow_arg_area);
                    va.overflow_arg_area += 8;
                    return v;
                }
                return 0;
            };
            auto next_fp = [&]() -> double {
                if (va.fp_offset <= 160 && reinterpret_cast<uintptr_t>(va.reg_save_area) > 0x1000) {
                    double v = *reinterpret_cast<const double*>(va.reg_save_area + va.fp_offset);
                    va.fp_offset += 16;
                    return v;
                }
                if (reinterpret_cast<uintptr_t>(va.overflow_arg_area) > 0x1000) {
                    double v = *reinterpret_cast<const double*>(va.overflow_arg_area);
                    va.overflow_arg_area += 8;
                    return v;
                }
                return 0.0;
            };
            const char* fmt = reinterpret_cast<const char*>(guest_rdx);
            std::string out;
            out.reserve(128);
            for (size_t i = 0; fmt[i] != '\0'; ++i) {
                if (fmt[i] != '%') {
                    out.push_back(fmt[i]);
                    continue;
                }
                ++i;
                if (fmt[i] == '%') {
                    out.push_back('%');
                    continue;
                }
                size_t spec_start = i - 1;
                while (fmt[i] == '-' || fmt[i] == '+' || fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0') ++i;
                if (fmt[i] == '*') { (void)next_gp(); ++i; }
                else { while (fmt[i] >= '0' && fmt[i] <= '9') ++i; }
                if (fmt[i] == '.') {
                    ++i;
                    if (fmt[i] == '*') { (void)next_gp(); ++i; }
                    else { while (fmt[i] >= '0' && fmt[i] <= '9') ++i; }
                }
                bool is_long = false;
                while (fmt[i] == 'h' || fmt[i] == 'l' || fmt[i] == 'j' || fmt[i] == 'z' || fmt[i] == 't' || fmt[i] == 'L') {
                    if (fmt[i] == 'l' || fmt[i] == 'z' || fmt[i] == 'j' || fmt[i] == 't') is_long = true;
                    ++i;
                }
                char conv = fmt[i];
                if (conv == '\0') break;
                char tmp[128]{};
                if (conv == 's') {
                    uint64_t s_ptr = next_gp();
                    const char* s_val = (s_ptr > 0x1000) ? reinterpret_cast<const char*>(s_ptr) : "";
                    out.append(s_val);
                } else if (conv == 'c') {
                    out.push_back(static_cast<char>(next_gp()));
                } else if (conv == 'd' || conv == 'i') {
                    uint64_t v = next_gp();
                    std::snprintf(tmp, sizeof(tmp), "%lld", is_long ? static_cast<long long>(v) : static_cast<long long>(static_cast<int32_t>(v)));
                    out.append(tmp);
                } else if (conv == 'u' || conv == 'x' || conv == 'X' || conv == 'p' || conv == 'o') {
                    uint64_t v = next_gp();
                    std::string sub_fmt(fmt + spec_start, i - spec_start + 1);
                    if (conv == 'p') std::snprintf(tmp, sizeof(tmp), "0x%llx", static_cast<unsigned long long>(v));
                    else if (conv == 'x') std::snprintf(tmp, sizeof(tmp), "%llx", is_long ? static_cast<unsigned long long>(v) : static_cast<unsigned long long>(static_cast<uint32_t>(v)));
                    else if (conv == 'X') std::snprintf(tmp, sizeof(tmp), "%llX", is_long ? static_cast<unsigned long long>(v) : static_cast<unsigned long long>(static_cast<uint32_t>(v)));
                    else std::snprintf(tmp, sizeof(tmp), "%llu", is_long ? static_cast<unsigned long long>(v) : static_cast<unsigned long long>(static_cast<uint32_t>(v)));
                    out.append(tmp);
                } else if (conv == 'f' || conv == 'F' || conv == 'e' || conv == 'E' || conv == 'g' || conv == 'G') {
                    double dv = next_fp();
                    std::snprintf(tmp, sizeof(tmp), "%g", dv);
                    out.append(tmp);
                }
            }
            if (guest_rdi > 0x1000 && guest_rsi > 0) {
                size_t copy_len = (std::min)(out.size(), static_cast<size_t>(guest_rsi - 1));
                std::memcpy(reinterpret_cast<void*>(guest_rdi), out.data(), copy_len);
                reinterpret_cast<char*>(guest_rdi)[copy_len] = '\0';
            }
            return static_cast<uint64_t>(out.size());
        }
        if (meta.nid == "kiZSXIWd9vg" || meta.resolved_name == "strcpy") {
            if (guest_rdi > 0x1000 && guest_rsi > 0x1000) {
                std::strcpy(reinterpret_cast<char*>(guest_rdi), reinterpret_cast<const char*>(guest_rsi));
            }
            return guest_rdi;
        }
        if (meta.nid == "Ovb2dSJOAuE" || meta.resolved_name == "strcmp") {
            if (guest_rdi > 0x1000 && guest_rsi > 0x1000) {
                return static_cast<uint64_t>(static_cast<int64_t>(std::strcmp(
                    reinterpret_cast<const char*>(guest_rdi),
                    reinterpret_cast<const char*>(guest_rsi))));
            }
            return 0;
        }
        if (meta.nid == "aesyjrHVWy4" || meta.resolved_name == "strncmp") {
            if (guest_rdi > 0x1000 && guest_rsi > 0x1000) {
                return static_cast<uint64_t>(static_cast<int64_t>(std::strncmp(
                    reinterpret_cast<const char*>(guest_rdi),
                    reinterpret_cast<const char*>(guest_rsi),
                    static_cast<size_t>(guest_rdx))));
            }
            return 0;
        }
        if (meta.nid == "DfivPArhucg" || meta.resolved_name == "memcmp") {
            if (guest_rdi > 0x1000 && guest_rsi > 0x1000 && guest_rdx > 0) {
                return static_cast<uint64_t>(static_cast<int64_t>(std::memcmp(
                    reinterpret_cast<const void*>(guest_rdi),
                    reinterpret_cast<const void*>(guest_rsi),
                    static_cast<size_t>(guest_rdx))));
            }
            return 0;
        }
        if (meta.nid == "+P6FRGH4LfA" || meta.resolved_name == "memmove") {
            if (guest_rdi > 0x1000 && guest_rsi > 0x1000 && guest_rdx > 0 && guest_rdx < (1ULL << 28)) {
                std::memmove(
                    reinterpret_cast<void*>(guest_rdi),
                    reinterpret_cast<const void*>(guest_rsi),
                    static_cast<size_t>(guest_rdx));
            }
            return guest_rdi;
        }
        if (meta.nid == "ob5xAW4ln-0" || meta.resolved_name == "strchr") {
            if (guest_rdi > 0x1000) {
                const char* p = std::strchr(reinterpret_cast<const char*>(guest_rdi), static_cast<int>(guest_rsi));
                return reinterpret_cast<uint64_t>(p);
            }
            return 0;
        }
        if (meta.nid == "9yDWMxEFdJU" || meta.resolved_name == "strrchr") {
            if (guest_rdi > 0x1000) {
                const char* p = std::strrchr(reinterpret_cast<const char*>(guest_rdi), static_cast<int>(guest_rsi));
                return reinterpret_cast<uint64_t>(p);
            }
            return 0;
        }
        if (meta.nid == "viiwFMaNamA" || meta.resolved_name == "strstr") {
            if (guest_rdi > 0x1000 && guest_rsi > 0x1000) {
                const char* p = std::strstr(reinterpret_cast<const char*>(guest_rdi), reinterpret_cast<const char*>(guest_rsi));
                return reinterpret_cast<uint64_t>(p);
            }
            return 0;
        }
        if (meta.nid == "8u8lPzUEq+U" || meta.resolved_name == "memchr") {
            if (guest_rdi > 0x1000 && guest_rdx > 0) {
                const void* p = std::memchr(reinterpret_cast<const void*>(guest_rdi), static_cast<int>(guest_rsi), static_cast<size_t>(guest_rdx));
                return reinterpret_cast<uint64_t>(p);
            }
            return 0;
        }
        if (meta.nid == "5jNubw4vlAA" || meta.resolved_name == "strnlen") {
            if (guest_rdi > 0x1000) {
                return static_cast<uint64_t>(strnlen(reinterpret_cast<const char*>(guest_rdi), static_cast<size_t>(guest_rsi)));
            }
            return 0;
        }
        if (meta.nid == "gQX+4GDQjpM" || meta.resolved_name == "malloc") {
            size_t sz = static_cast<size_t>(guest_rdi);
            if (sz == 0 || sz > (1ULL << 30)) sz = 64;
            return reinterpret_cast<uint64_t>(std::calloc(1, sz));
        }
        if (meta.nid == "Y7aJ1uydPMo" || meta.resolved_name == "realloc") {
            size_t sz = static_cast<size_t>(guest_rsi);
            if (sz == 0 || sz > (1ULL << 30)) sz = 64;
            return reinterpret_cast<uint64_t>(std::realloc(reinterpret_cast<void*>(guest_rdi), sz));
        }
        if (meta.nid == "tIhsqj0qsFE" || meta.resolved_name == "free") {
            return 0;
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
            0x48, 0x8B, 0x45, 0x10,                   // mov rax, [rbp+0x10] (7th SysV arg on stack)
            0x48, 0x89, 0x44, 0x24, 0x38,             // mov [rsp+0x38], rax
            0x48, 0x89, 0x4C, 0x24, 0x20,             // mov [rsp+0x20], rcx
            0x4C, 0x89, 0x44, 0x24, 0x28,             // mov [rsp+0x28], r8
            0x4C, 0x89, 0x4C, 0x24, 0x30,             // mov [rsp+0x30], r9
            0x49, 0x89, 0xD1,                         // mov r9, rdx
            0x49, 0x89, 0xF0,                         // mov r8, rsi
            0x48, 0x89, 0xFA,                         // mov rdx, rdi
            0xB9, 0x00, 0x00, 0x00, 0x00,             // mov ecx, slot_idx   (offset 57)
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,       // movabs rax, &HleDispatchTrampoline (offset 63)
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
        std::memcpy(code + 57, &slot_idx, sizeof(uint32_t));
        uint64_t fn_addr = reinterpret_cast<uint64_t>(&HleDispatchTrampoline);
        std::memcpy(code + 63, &fn_addr, sizeof(uint64_t));
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

size_t NidRegistry::GetTotalDispatchedCalls() {
    return g_call_counter.load(std::memory_order_relaxed);
}

void NidRegistry::PrintLiveTelemetrySummary() {
    std::unordered_map<std::string, uint64_t> counts_copy;
    std::unordered_set<std::string> unique_nids;
    for (const auto& slot : g_bound_slots) {
        if (slot.call_count > 0) {
            counts_copy[slot.library] += slot.call_count;
            unique_nids.insert(slot.nid);
        }
    }
    size_t unique_count = unique_nids.size();
    std::cout << "[+] HLE Bridge Live Call Telemetry (" << g_call_counter.load()
              << " total calls across " << unique_count << " unique NIDs):\n";
    for (const auto& [lib, count] : counts_copy) {
        std::cout << "    [" << std::setw(24) << std::left << lib << "] : " << count << " calls\n";
    }
}

void NidRegistry::SetVerboseUnhandled(bool enabled) {
    g_verbose_unhandled = enabled;
}

void NidRegistry::SetGameMainThreadId(uint32_t host_tid) {
    g_game_main_host_tid.store(host_tid, std::memory_order_relaxed);
}

void NidRegistry::PrintGameMainTimeline() {
    std::vector<GameMainCallRecord> copy;
    {
        std::lock_guard<std::mutex> lock(g_telemetry_mutex);
        copy = g_main_thread_timeline;
    }
    std::cout << "[+] Game main() Primary Thread Execution Timeline ("
              << copy.size() << " compressed call phases):\n";
    size_t start_idx = (copy.size() > 32) ? (copy.size() - 32) : 0;
    for (size_t i = start_idx; i < copy.size(); ++i) {
        const auto& rec = copy[i];
        std::cout << "    [Phase #" << std::setw(2) << (i + 1) << " | Global #"
                  << std::setw(5) << rec.global_seq << "] "
                  << std::setw(18) << std::left << rec.library << " :: "
                  << std::setw(36) << rec.resolved_name
                  << " (" << rec.nid << ") x" << rec.repeat_count
                  << " | rdi=0x" << std::hex << rec.rdi
                  << " rsi=0x" << rec.rsi << " rdx=0x" << rec.rdx << std::dec << "\n";
    }
}

} // namespace yotei::hle
