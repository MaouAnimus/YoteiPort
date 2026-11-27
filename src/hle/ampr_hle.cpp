#include "hle/ampr_hle.h"
#include "kernel/filesystem.h"
#include "kernel/memory.h"
#include <cstring>
#include <iostream>

namespace yotei::hle {

AmprHleManager& AmprHleManager::Instance() {
    static AmprHleManager instance;
    return instance;
}

AmprCommandBufferState& AmprHleManager::GetOrCreateCb(uint64_t guest_cb_ptr) {
    auto it = cmd_buffers_.find(guest_cb_ptr);
    if (it == cmd_buffers_.end()) {
        AmprCommandBufferState st{};
        st.guest_cmdbuf_ptr = guest_cb_ptr;
        it = cmd_buffers_.emplace(guest_cb_ptr, std::move(st)).first;
    }
    return it->second;
}

int32_t AmprHleManager::ExecuteCommandBuffer(AmprCommandBufferState& cb) {
    auto& vfs = kernel::VirtualFileSystem::Instance();
    auto& mem = kernel::GuestMemoryManager::Instance();

    for (const auto& cmd : cb.commands) {
        switch (cmd.type) {
            case AmprCmdType::ReadFile:
            case AmprCmdType::ReadFileScatter:
            case AmprCmdType::ReadFileGatherScatter: {
                if (cmd.dst_or_target_addr != 0 && cmd.length_or_value > 0) {
                    int64_t read_bytes = vfs.AprReadFileById(
                        cmd.file_id,
                        reinterpret_cast<void*>(cmd.dst_or_target_addr),
                        cmd.length_or_value,
                        cmd.file_offset);
                    if (read_bytes > 0) {
                        total_bytes_streamed_ += static_cast<size_t>(read_bytes);
                    }
                }
                break;
            }
            case AmprCmdType::MapBegin:
            case AmprCmdType::MapDirectBegin: {
                if (cmd.dst_or_target_addr != 0 && cmd.length_or_value > 0) {
                    uint64_t vaddr = cmd.dst_or_target_addr;
                    mem.MapMemory(&vaddr, cmd.length_or_value, 0x3, 0, cmd.file_offset, 0x10000ULL, "ampr_map");
                }
                break;
            }
            case AmprCmdType::WriteAddressOnCompletion: {
                if (cmd.dst_or_target_addr != 0) {
                    *reinterpret_cast<uint64_t*>(cmd.dst_or_target_addr) = cmd.length_or_value;
                }
                break;
            }
            case AmprCmdType::WriteCounterOnCompletion: {
                if (cmd.dst_or_target_addr != 0) {
                    *reinterpret_cast<uint32_t*>(cmd.dst_or_target_addr) =
                        static_cast<uint32_t>(cmd.length_or_value);
                }
                break;
            }
            default:
                break;
        }
    }
    cb.commands.clear();
    cb.current_offset = 0;
    ++submitted_buffers_;
    return 0; // SCE_OK
}

bool AmprHleManager::DispatchNid(
    const std::string& nid,
    const std::string& resolved_name,
    uint64_t rdi,
    uint64_t rsi,
    uint64_t rdx,
    uint64_t rcx,
    uint64_t r8,
    uint64_t r9,
    uint64_t* out_ret,
    uint64_t stack_arg0) {
    if (resolved_name.rfind("Ampr::", 0) != 0 &&
        resolved_name.rfind("Apr::", 0) != 0 &&
        resolved_name.rfind("sceKernelApr", 0) != 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto& vfs = kernel::VirtualFileSystem::Instance();

    // 1. MeasureCommandSize* functions always return a fixed 32-byte command size
    if (resolved_name.find("Measure") != std::string::npos) {
        *out_ret = 32;
        return true;
    }

    // 2. APR file stat & file size by ID (sceKernelAprGetFileStat / sceKernelAprGetFileSize)
    if (nid == "ApkYaHb8Sek" || resolved_name == "sceKernelAprGetFileStat" || resolved_name == "Apr::GetFileStat") {
        *out_ret = static_cast<uint64_t>(vfs.AprStatFileById(
            static_cast<uint32_t>(rdi),
            reinterpret_cast<kernel::SceKernelStat*>(rsi)));
        return true;
    }
    if (nid == "WvEu7yl3Ivg" || resolved_name == "sceKernelAprGetFileSize" || resolved_name == "Apr::GetFileSize") {
        *out_ret = static_cast<uint64_t>(vfs.AprGetFileSize(
            static_cast<uint32_t>(rdi),
            reinterpret_cast<uint64_t*>(rsi)));
        return true;
    }

    // 2b. APR path resolution functions
    if (nid == "C+Khtbbx2g8" || nid == "w5fcCG+t31g" ||
        resolved_name == "sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach" ||
        resolved_name == "sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes" ||
        resolved_name == "Apr::ResolveFilepathsWithPrefixToIdsAndFileSizesForEach" ||
        resolved_name == "Apr::ResolveFilepathsWithPrefixToIdsAndFileSizes") {
        // (const char* prefix, const char* const* paths, uint32_t count, uint32_t* ids_out, uint64_t* sizes_out, int32_t* errs_out)
        std::string prefix = (rdi > 0x1000) ? std::string(reinterpret_cast<const char*>(rdi)) : "";
        const auto* paths  = reinterpret_cast<const char* const*>(rsi);
        uint32_t count     = static_cast<uint32_t>(rdx);
        auto* ids_out      = (rcx > 0x1000) ? reinterpret_cast<uint32_t*>(rcx) : nullptr;
        auto* sizes_out    = (r8  > 0x1000) ? reinterpret_cast<uint64_t*>(r8)  : nullptr;
        auto* errs_out     = (r9  > 0x1000) ? reinterpret_cast<int32_t*>(r9)   : nullptr;
        int32_t first_err  = 0;
        if (paths && count > 0 && count < 65536) {
            for (uint32_t i = 0; i < count; ++i) {
                std::string full = prefix + (paths[i] ? std::string(paths[i]) : "");
                uint32_t fid = 0xFFFFFFFFU;
                uint64_t fsz = 0;
                int32_t rc = vfs.AprResolvePath(full, &fid, &fsz);
                if (ids_out) ids_out[i] = fid;
                if (sizes_out) sizes_out[i] = fsz;
                if (errs_out) errs_out[i] = rc;
                if (rc != 0 && first_err == 0) first_err = rc;
            }
        }
        *out_ret = static_cast<uint64_t>(first_err);
        return true;
    }
    if (nid == "i3HWvW35jao" || nid == "VB-BtuIW8Xc" ||
        resolved_name == "sceKernelAprResolveFilepathsWithPrefixToIds" ||
        resolved_name == "sceKernelAprResolveFilepathsWithPrefixToIdsForEach") {
        // (const char* prefix, const char* const* paths, uint32_t count, uint32_t* ids_out, int32_t* errs_out)
        std::string prefix = (rdi > 0x1000) ? std::string(reinterpret_cast<const char*>(rdi)) : "";
        const auto* paths  = reinterpret_cast<const char* const*>(rsi);
        uint32_t count     = static_cast<uint32_t>(rdx);
        auto* ids_out      = (rcx > 0x1000) ? reinterpret_cast<uint32_t*>(rcx) : nullptr;
        auto* errs_out     = (r8  > 0x1000) ? reinterpret_cast<int32_t*>(r8)   : nullptr;
        int32_t first_err  = 0;
        if (paths && count > 0 && count < 65536) {
            for (uint32_t i = 0; i < count; ++i) {
                std::string full = prefix + (paths[i] ? std::string(paths[i]) : "");
                uint32_t fid = 0xFFFFFFFFU;
                uint64_t fsz = 0;
                int32_t rc = vfs.AprResolvePath(full, &fid, &fsz);
                if (ids_out) ids_out[i] = fid;
                if (errs_out) errs_out[i] = rc;
                if (rc != 0 && first_err == 0) first_err = rc;
            }
        }
        *out_ret = static_cast<uint64_t>(first_err);
        return true;
    }
    if (nid == "gEpBkcwxUjw" || nid == "QzB4O+bJQyA" ||
        resolved_name == "sceKernelAprResolveFilepathsToIdsAndFileSizes" ||
        resolved_name == "sceKernelAprResolveFilepathsToIdsAndFileSizesForEach" ||
        resolved_name == "Apr::ResolveFilepathsToIdsAndFileSizesForEach" ||
        resolved_name == "Apr::ResolveFilepathsToIdsAndFileSizes") {
        // (const char* const* paths, uint32_t count, uint32_t* ids_out, uint64_t* sizes_out, int32_t* errs_out)
        const auto* paths = reinterpret_cast<const char* const*>(rdi);
        uint32_t count    = static_cast<uint32_t>(rsi);
        auto* ids_out     = (rdx > 0x1000) ? reinterpret_cast<uint32_t*>(rdx) : nullptr;
        auto* sizes_out   = (rcx > 0x1000) ? reinterpret_cast<uint64_t*>(rcx) : nullptr;
        auto* errs_out    = (r8  > 0x1000) ? reinterpret_cast<int32_t*>(r8)   : nullptr;
        int32_t first_err = 0;
        if (paths && count > 0 && count < 65536) {
            for (uint32_t i = 0; i < count; ++i) {
                std::string full = paths[i] ? std::string(paths[i]) : "";
                uint32_t fid = 0xFFFFFFFFU;
                uint64_t fsz = 0;
                int32_t rc = vfs.AprResolvePath(full, &fid, &fsz);
                if (ids_out) ids_out[i] = fid;
                if (sizes_out) sizes_out[i] = fsz;
                if (errs_out) errs_out[i] = rc;
                if (rc != 0 && first_err == 0) first_err = rc;
            }
        }
        *out_ret = static_cast<uint64_t>(first_err);
        return true;
    }
    if (nid == "WT-5NKy42fw" || nid == "eYAh2vlCY-U" ||
        resolved_name == "sceKernelAprResolveFilepathsToIds" ||
        resolved_name == "sceKernelAprResolveFilepathsToIdsForEach" ||
        resolved_name == "Apr::ResolveFilepathsToIds") {
        // (const char* const* paths, uint32_t count, uint32_t* ids_out, int32_t* err_out)
        // NOTE: rcx is 4-byte int32_t* err_out (at [rbp-0x2c] in 0x800c9d4e0), NOT 8-byte uint64_t* sizes_out!
        const auto* paths = reinterpret_cast<const char* const*>(rdi);
        uint32_t count    = static_cast<uint32_t>(rsi);
        auto* ids_out     = (rdx > 0x1000) ? reinterpret_cast<uint32_t*>(rdx) : nullptr;
        auto* errs_out    = (rcx > 0x1000) ? reinterpret_cast<int32_t*>(rcx)  : nullptr;
        int32_t first_err = 0;
        if (paths && count > 0 && count < 65536) {
            for (uint32_t i = 0; i < count; ++i) {
                std::string full = paths[i] ? std::string(paths[i]) : "";
                uint32_t fid = 0xFFFFFFFFU;
                uint64_t fsz = 0;
                int32_t rc = vfs.AprResolvePath(full, &fid, &fsz);
                if (ids_out) ids_out[i] = fid;
                if (errs_out) errs_out[i] = rc;
                if (rc != 0 && first_err == 0) first_err = rc;
            }
        }
        *out_ret = static_cast<uint64_t>(first_err);
        return true;
    }

    // 3. CommandBuffer lifecycle (accounting for 1-slot shift in kyty_hle_table vs 0x8000f2850..0x8000f2c90 wrappers)
    if (nid == "8aI7R7WaOlc" || nid == "a8uLzYY--tM" ||
        resolved_name == "Ampr::CommandBufferConstructor") {
        // 0x8000f2b70 calls 8aI7R7WaOlc (CommandBuffer::CommandBuffer) then a8uLzYY--tM (AprCommandBuffer::AprCommandBuffer)
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.clear();
        cb.current_offset = 0;
        *out_ret = 0;
        return true;
    }
    if (nid == "GuchCTefuZw") {
        // 0x8000f2ba0 calls Qs1xtplKo0U then GuchCTefuZw (CommandBuffer::~CommandBuffer)
        cmd_buffers_.erase(rdi);
        *out_ret = 0;
        return true;
    }
    if (nid == "Qs1xtplKo0U") {
        // In 0x8000f2ba0, Qs1xtplKo0U is called with (rdi=this, rsi=this+0x18, rdx=this+0x20); in synthetic test it is called as constructor
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.clear();
        cb.current_offset = 0;
        *out_ret = 0;
        return true;
    }
    if (nid == "N-FSPA4S3nI" || resolved_name == "Ampr::CommandBufferSetBuffer") {
        // 0x8000f2860 -> 0x8017e8300 (N-FSPA4S3nI): CommandBuffer::setBuffer(this=rdi, buf=rsi, size=rdx)
        auto& cb = GetOrCreateCb(rdi);
        cb.buffer_base_addr = rsi;
        cb.buffer_max_size  = rdx;
        cb.current_offset   = 0;
        cb.commands.clear();
        *out_ret = 0;
        return true;
    }
    if (nid == "baQO9ez2gL4" || nid == "ULvXMDz56po" || nid == "VEDMaQmJZng" || nid == "YPxkUDhgoNI" ||
        resolved_name == "Ampr::CommandBufferReset" ||
        resolved_name == "Ampr::CommandBufferClearBuffer" ||
        resolved_name == "Ampr::AprCommandBufferResetGatherScatterState") {
        auto& cb = GetOrCreateCb(rdi);
        cb.current_offset = 0;
        cb.commands.clear();
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferGetBufferBaseAddress") {
        *out_ret = GetOrCreateCb(rdi).buffer_base_addr;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferGetSize" ||
        resolved_name == "Ampr::CommandBufferGetCurrentOffset") {
        *out_ret = GetOrCreateCb(rdi).current_offset;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferGetNumCommands") {
        *out_ret = GetOrCreateCb(rdi).commands.size();
        return true;
    }

    // 4. APR Read & Map commands
    if (nid == "mQ16-QdKv7k") {
        // 0x8000f2bd0 -> 0x8017e84a0 (mQ16-QdKv7k):
        // AprCommandBuffer::readFile(this=rdi, this+0x18=rsi, this+0x20=rdx, file_id=ecx, dst=r8, size=r9, offset=stack_arg0)
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::ReadFile, static_cast<uint32_t>(rcx), r8, r9, stack_arg0, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (nid == "mZSbNJVJpV8" || resolved_name == "Ampr::AprCommandBufferReadFile") {
        auto& cb = GetOrCreateCb(rdi);
        if (rsi == rdi + 0x18 && rdx == rdi + 0x20) {
            // 0x8000f2c00 -> 0x8017e84b0 (mZSbNJVJpV8): readFileScatter(this=rdi, this+0x18=rsi, this+0x20=rdx, dst=rcx, size=r8)
            cb.commands.push_back({AmprCmdType::ReadFileScatter, cb.gather_file_id, rcx, r8, cb.gather_file_off, ""});
        } else {
            // Synthetic test call: (cb=rdi, void* dst=rsi, uint32_t file_id=rdx, uint64_t size=rcx, uint64_t offset=r8)
            cb.commands.push_back({AmprCmdType::ReadFile, static_cast<uint32_t>(rdx), rsi, rcx, r8, ""});
        }
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (nid == "Jg-AgkdJHkk" || resolved_name == "Ampr::AprCommandBufferReadFileGather") {
        auto& cb = GetOrCreateCb(rdi);
        if (rsi == rdi + 0x18 && rdx == rdi + 0x20) {
            cb.gather_file_id  = static_cast<uint32_t>(rcx);
            cb.gather_file_off = r8;
        } else {
            cb.gather_file_id  = static_cast<uint32_t>(rsi);
            cb.gather_len      = rdx;
            cb.gather_file_off = rcx;
        }
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (nid == "BVmR1H8l+XI" || resolved_name == "Ampr::AprCommandBufferReadFileScatter") {
        auto& cb = GetOrCreateCb(rdi);
        if (rsi == rdi + 0x18 && rdx == rdi + 0x20) {
            cb.gather_file_id  = static_cast<uint32_t>(rcx);
            cb.gather_file_off = r8;
            cb.gather_len      = r9;
        } else {
            cb.commands.push_back({
                AmprCmdType::ReadFileScatter,
                cb.gather_file_id,
                rsi,
                rdx,
                cb.gather_file_off + rcx,
                ""
            });
        }
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::AprCommandBufferReadFileGatherScatter") {
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::ReadFileGatherScatter, static_cast<uint32_t>(rdx), rsi, rcx, r8, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (nid == "Eul7AGEpjLo" || nid == "bFEs0Gs6D2A" || nid == "X169CE6G3Y4" ||
        resolved_name == "Ampr::AprCommandBufferMapBegin" ||
        resolved_name == "Ampr::AprCommandBufferMapDirectBegin") {
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::MapBegin, 0, rsi, rdx, rcx, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (nid == "j0+3uJMxYJY" || nid == "jK+yuYCI7MA" ||
        resolved_name == "Ampr::CommandBufferWriteAddressOnCompletion" ||
        resolved_name == "Ampr::CommandBufferWriteAddressFromCounterOnCompletion" ||
        resolved_name == "Ampr::CommandBufferWriteAddressFromTimeCounterOnCompletion" ||
        resolved_name == "Ampr::CommandBufferWriteAddressFromCounterPairOnCompletion") {
        // 0x8000f2970 -> 0x8017e8390 (j0+3uJMxYJY): writeAddressOnCompletion(cb=rdi, dst_addr=rsi, val=rdx, mode=ecx)
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::WriteAddressOnCompletion, 0, rsi, rdx, 0, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (nid == "bt3LHR9xjK4" || resolved_name == "Ampr::CommandBufferWriteCounterOnCompletion") {
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::WriteCounterOnCompletion, 0, rsi, rdx, 0, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }

    // 5. Submission & Wait (sceKernelAprSubmitCommandBuffer* & Apr::SubmitCommandBuffer*)
    if (nid == "eE4Szl8sil8" || nid == "qvMUCyyaCSI" || nid == "ASoW5WE-UPo" ||
        resolved_name == "sceKernelAprSubmitCommandBuffer" ||
        resolved_name == "sceKernelAprSubmitCommandBufferAndGetId" ||
        resolved_name == "sceKernelAprSubmitCommandBufferAndGetResult" ||
        resolved_name == "Apr::SubmitCommandBuffer" ||
        resolved_name == "Apr::SubmitCommandBufferAndGetId" ||
        resolved_name == "Apr::SubmitCommandBufferAndGetResult") {
        auto& cb = GetOrCreateCb(rdi);
        ExecuteCommandBuffer(cb);
        if (nid == "qvMUCyyaCSI" ||
            resolved_name == "sceKernelAprSubmitCommandBufferAndGetId" ||
            resolved_name == "Apr::SubmitCommandBufferAndGetId") {
            // 0x8000f2ed0 (cb=rdi, prio=esi, uint32_t* id_out=rdx)
            if (rdx > 0x1000) {
                *reinterpret_cast<uint32_t*>(rdx) = next_submit_id_++;
            } else if (rsi > 0x1000) {
                *reinterpret_cast<uint32_t*>(rsi) = next_submit_id_++;
            }
        } else if (nid == "ASoW5WE-UPo" ||
                   resolved_name == "sceKernelAprSubmitCommandBufferAndGetResult" ||
                   resolved_name == "Apr::SubmitCommandBufferAndGetResult") {
            // 0x8000f2f00 (cb=rdi, prio=esi, int32_t* res_out=rdx, uint32_t* id_out=rcx)
            if (rdx > 0x1000) *reinterpret_cast<int32_t*>(rdx) = 0;
            if (rcx > 0x1000) *reinterpret_cast<uint32_t*>(rcx) = next_submit_id_++;
        }
        *out_ret = 0;
        return true;
    }
    if (nid == "rqwFKI4PAiM" ||
        resolved_name == "sceKernelAprWaitCommandBuffer" ||
        resolved_name == "Apr::WaitCommandBuffer") {
        *out_ret = 0;
        return true;
    }

    // Default for markers/NOPs/waits
    auto& cb = GetOrCreateCb(rdi);
    cb.current_offset += 32;
    *out_ret = 0;
    return true;
}

} // namespace yotei::hle
