#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yotei::graphics {

// AMD RDNA2 / PS5 AGC PM4 Type-3 Opcodes
enum class Pm4Opcode : uint8_t {
    IT_NOP                    = 0x10,
    IT_SET_BASE               = 0x11,
    IT_CLEAR_STATE            = 0x12,
    IT_INDEX_BUFFER_SIZE      = 0x13,
    IT_DISPATCH_DIRECT        = 0x15,
    IT_DISPATCH_INDIRECT      = 0x16,
    IT_ATOMIC_MEM             = 0x1E,
    IT_OCCLUSION_QUERY        = 0x1F,
    IT_SET_PREDICATION        = 0x20,
    IT_REG_RMW                = 0x21,
    IT_COND_EXEC              = 0x22,
    IT_PRED_EXEC              = 0x23,
    IT_DRAW_INDIRECT          = 0x24,
    IT_DRAW_INDEX_INDIRECT    = 0x25,
    IT_INDEX_BASE             = 0x26,
    IT_DRAW_INDEX_2           = 0x27,
    IT_CONTEXT_CONTROL        = 0x28,
    IT_INDEX_TYPE             = 0x2A,
    IT_DRAW_INDIRECT_MULTI    = 0x2C,
    IT_DRAW_INDEX_AUTO        = 0x2D,
    IT_NUM_INSTANCES          = 0x2F,
    IT_INDIRECT_BUFFER_CNST   = 0x33,
    IT_STRMOUT_BUFFER_UPDATE  = 0x34,
    IT_DRAW_INDEX_OFFSET_2    = 0x35,
    IT_WRITE_DATA             = 0x37,
    IT_MEM_SEMAPHORE          = 0x39,
    IT_WAIT_REG_MEM           = 0x3C,
    IT_INDIRECT_BUFFER        = 0x3F,
    IT_COPY_DATA              = 0x40,
    IT_PFP_SYNC_ME            = 0x42,
    IT_EVENT_WRITE            = 0x46,
    IT_EVENT_WRITE_EOP        = 0x47,
    IT_EVENT_WRITE_EOS        = 0x48,
    IT_RELEASE_MEM            = 0x49,
    IT_DMA_DATA               = 0x50,
    IT_ACQUIRE_MEM            = 0x58,
    IT_REWIND                 = 0x59,
    IT_SET_Config_REG         = 0x68,
    IT_SET_CONTEXT_REG        = 0x69,
    IT_SET_SH_REG             = 0x76,
    IT_SET_UCONFIG_REG        = 0x79,
};

struct DecodedPm4Packet {
    uint8_t  opcode;
    uint16_t dword_count;
    std::string name;
    std::string details;
};

struct AgcFrameStats {
    uint64_t dcb_submissions = 0;
    uint64_t acb_submissions = 0;
    uint64_t draw_calls      = 0;
    uint64_t dispatches      = 0;
    uint64_t flips           = 0;
    std::vector<std::string> active_markers;
    std::vector<std::string> marker_history;
};

struct AgcDrawState {
    uint32_t index_type = 0;        // 0 = 16-bit, 1 = 32-bit
    uint64_t index_base = 0;        // GPU VAddr
    uint32_t index_buffer_size = 0; // element count
    uint32_t num_instances = 1;     // active instances
    uint32_t primitive_type = 4;    // 4 = TRIANGLE_LIST
};

class AgcPm4Backend {
public:
    static AgcPm4Backend& Instance();

    // Decode a raw RDNA2 PM4 command stream in guest memory
    std::vector<DecodedPm4Packet> DecodeCommandStream(const uint32_t* dwords, size_t dword_count);

    // Handle libSceAgc, libSceAgcDriver, and libSceVideoOut NID calls
    bool DispatchNid(
        const std::string& library,
        const std::string& nid,
        const std::string& resolved_name,
        uint64_t rdi,
        uint64_t rsi,
        uint64_t rdx,
        uint64_t rcx,
        uint64_t r8,
        uint64_t r9,
        uint64_t* out_ret);

    const AgcFrameStats& GetStats() const { return stats_; }

private:
    AgcPm4Backend() = default;

    static const char* GetOpcodeName(uint8_t op);

    std::mutex mutex_;
    AgcFrameStats stats_;
    AgcDrawState draw_state_{};
    std::unordered_map<uint32_t, uint32_t> context_regs_;
    std::unordered_map<uint32_t, uint32_t> sh_regs_;
    std::unordered_map<uint32_t, uint32_t> uconfig_regs_;
};

} // namespace yotei::graphics
