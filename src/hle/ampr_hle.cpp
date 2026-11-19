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
    ++submitted_buffers_;
    return 0; // SCE_OK
}

bool AmprHleManager::DispatchNid(
    const std::string& /*nid*/,
    const std::string& resolved_name,
    uint64_t rdi,
    uint64_t rsi,
    uint64_t rdx,
    uint64_t rcx,
    uint64_t r8,
    uint64_t /*r9*/,
    uint64_t* out_ret) {
    if (resolved_name.rfind("Ampr::", 0) != 0 && resolved_name.rfind("Apr::", 0) != 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto& vfs = kernel::VirtualFileSystem::Instance();

    // 1. MeasureCommandSize* functions always return a fixed 32-byte or 64-byte command size
    if (resolved_name.find("Measure") != std::string::npos) {
        *out_ret = 32;
        return true;
    }

    // 2. APR path resolution functions
    if (resolved_name == "Apr::ResolveFilepathsWithPrefixToIdsAndFileSizesForEach" ||
        resolved_name == "Apr::ResolveFilepathsWithPrefixToIdsAndFileSizes") {
        // (const char* prefix, const char* const* paths, uint32_t count, uint32_t* ids_out, uint64_t* sizes_out, int32_t* errs_out)
        std::string prefix = (rdi != 0) ? std::string(reinterpret_cast<const char*>(rdi)) : "";
        const auto* paths  = reinterpret_cast<const char* const*>(rsi);
        uint32_t count     = static_cast<uint32_t>(rdx);
        auto* ids_out      = reinterpret_cast<uint32_t*>(rcx);
        auto* sizes_out    = reinterpret_cast<uint64_t*>(r8);
        if (paths && count > 0 && count < 65536) {
            for (uint32_t i = 0; i < count; ++i) {
                std::string full = prefix + (paths[i] ? std::string(paths[i]) : "");
                uint32_t fid = 0;
                uint64_t fsz = 0;
                vfs.AprResolvePath(full, &fid, &fsz);
                if (ids_out) ids_out[i] = fid;
                if (sizes_out) sizes_out[i] = fsz;
            }
        }
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Apr::ResolveFilepathsToIdsAndFileSizesForEach" ||
        resolved_name == "Apr::ResolveFilepathsToIdsAndFileSizes" ||
        resolved_name == "Apr::ResolveFilepathsToIds") {
        const auto* paths = reinterpret_cast<const char* const*>(rdi);
        uint32_t count    = static_cast<uint32_t>(rsi);
        auto* ids_out     = reinterpret_cast<uint32_t*>(rdx);
        auto* sizes_out   = reinterpret_cast<uint64_t*>(rcx);
        if (paths && count > 0 && count < 65536) {
            for (uint32_t i = 0; i < count; ++i) {
                std::string full = paths[i] ? std::string(paths[i]) : "";
                uint32_t fid = 0;
                uint64_t fsz = 0;
                vfs.AprResolvePath(full, &fid, &fsz);
                if (ids_out) ids_out[i] = fid;
                if (sizes_out) sizes_out[i] = fsz;
            }
        }
        *out_ret = 0;
        return true;
    }

    // 3. CommandBuffer lifecycle
    if (resolved_name == "Ampr::CommandBufferConstructor" ||
        resolved_name == "Ampr::AprCommandBufferConstructor") {
        auto& cb = GetOrCreateCb(rdi);
        cb.cb_type = static_cast<uint32_t>(rsi);
        cb.commands.clear();
        cb.current_offset = 0;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferDestructor" ||
        resolved_name == "Ampr::AprCommandBufferDestructor") {
        cmd_buffers_.erase(rdi);
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferSetBuffer") {
        auto& cb = GetOrCreateCb(rdi);
        cb.buffer_base_addr = rsi;
        cb.buffer_max_size  = rdx;
        cb.current_offset   = 0;
        cb.commands.clear();
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferReset" ||
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
    if (resolved_name == "Ampr::AprCommandBufferReadFile") {
        // (cb, void* dst, uint32_t file_id, uint64_t size, uint64_t offset)
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::ReadFile, static_cast<uint32_t>(rdx), rsi, rcx, r8, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::AprCommandBufferReadFileGather") {
        // (cb, uint32_t file_id, uint64_t size, uint64_t offset)
        auto& cb = GetOrCreateCb(rdi);
        cb.gather_file_id  = static_cast<uint32_t>(rsi);
        cb.gather_len      = rdx;
        cb.gather_file_off = rcx;
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::AprCommandBufferReadFileScatter") {
        // (cb, void* dst, uint64_t size, uint64_t gather_offset)
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({
            AmprCmdType::ReadFileScatter,
            cb.gather_file_id,
            rsi,
            rdx,
            cb.gather_file_off + rcx,
            ""
        });
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
    if (resolved_name == "Ampr::AprCommandBufferMapBegin" ||
        resolved_name == "Ampr::AprCommandBufferMapDirectBegin") {
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::MapBegin, 0, rsi, rdx, rcx, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferWriteAddressOnCompletion" ||
        resolved_name == "Ampr::CommandBufferWriteAddressFromCounterOnCompletion" ||
        resolved_name == "Ampr::CommandBufferWriteAddressFromTimeCounterOnCompletion" ||
        resolved_name == "Ampr::CommandBufferWriteAddressFromCounterPairOnCompletion") {
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::WriteAddressOnCompletion, 0, rsi, rdx, 0, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Ampr::CommandBufferWriteCounterOnCompletion") {
        auto& cb = GetOrCreateCb(rdi);
        cb.commands.push_back({AmprCmdType::WriteCounterOnCompletion, 0, rsi, rdx, 0, ""});
        cb.current_offset += 32;
        *out_ret = 0;
        return true;
    }

    // 5. Submission & Wait
    if (resolved_name == "Apr::SubmitCommandBuffer" ||
        resolved_name == "Apr::SubmitCommandBufferAndGetId" ||
        resolved_name == "Apr::SubmitCommandBufferAndGetResult") {
        auto& cb = GetOrCreateCb(rdi);
        ExecuteCommandBuffer(cb);
        if (rsi != 0 && resolved_name == "Apr::SubmitCommandBufferAndGetId") {
            *reinterpret_cast<uint32_t*>(rsi) = next_submit_id_++;
        }
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Apr::WaitCommandBuffer") {
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
