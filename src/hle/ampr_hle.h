#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yotei::hle {

enum class AmprCmdType : uint32_t {
    Nop = 0,
    ReadFile,
    ReadFileGather,
    ReadFileScatter,
    ReadFileGatherScatter,
    ResetGatherScatterState,
    MapBegin,
    MapDirectBegin,
    MapEnd,
    WaitOnAddress,
    WaitOnCounter,
    WriteAddressOnCompletion,
    WriteCounterOnCompletion,
    WriteKernelEventQueue,
    Marker,
};

struct AmprCommand {
    AmprCmdType type;
    uint32_t file_id = 0;
    uint64_t dst_or_target_addr = 0;
    uint64_t length_or_value = 0;
    uint64_t file_offset = 0;
    std::string label;
};

struct AmprCommandBufferState {
    uint64_t guest_cmdbuf_ptr = 0;
    uint64_t buffer_base_addr = 0;
    uint64_t buffer_max_size  = 0;
    uint64_t current_offset   = 0;
    uint32_t cb_type          = 0;
    uint32_t gather_file_id   = 0;
    uint64_t gather_file_off  = 0;
    uint64_t gather_len       = 0;
    std::vector<AmprCommand> commands;
};

class AmprHleManager {
public:
    static AmprHleManager& Instance();

    // Dispatch any libSceAmpr or Apr::* / sceKernelApr* NID call; returns true if handled
    bool DispatchNid(
        const std::string& nid,
        const std::string& resolved_name,
        uint64_t rdi,
        uint64_t rsi,
        uint64_t rdx,
        uint64_t rcx,
        uint64_t r8,
        uint64_t r9,
        uint64_t* out_ret,
        uint64_t stack_arg0 = 0);

    size_t GetTotalSubmittedBuffers() const { return submitted_buffers_; }
    size_t GetTotalBytesStreamed() const { return total_bytes_streamed_; }

private:
    AmprHleManager() = default;

    AmprCommandBufferState& GetOrCreateCb(uint64_t guest_cb_ptr);
    int32_t ExecuteCommandBuffer(AmprCommandBufferState& cb);

    std::mutex mutex_;
    std::unordered_map<uint64_t, AmprCommandBufferState> cmd_buffers_;
    uint32_t next_submit_id_ = 1;
    size_t submitted_buffers_ = 0;
    size_t total_bytes_streamed_ = 0;
};

} // namespace yotei::hle
