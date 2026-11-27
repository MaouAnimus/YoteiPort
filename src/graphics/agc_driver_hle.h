#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yotei::graphics {

// Guest layout of sce::Agc::DrawCommandBuffer / AsyncComputeCommandBuffer header
struct GuestAgcCommandBuffer {
    uint32_t* cmd_base;      // 0x00: Start of command buffer allocation
    uint32_t* cmd_cur;       // 0x08: Current write cursor (advanced as PM4 packets are emitted)
    uint32_t* cmd_end;       // 0x10: End of current command buffer chunk
    uint64_t  callback_fn;   // 0x18: Out-of-memory / chunk callback
    uint64_t  user_data;     // 0x20: User data pointer
};

struct AgcRegisteredResource {
    uint32_t owner_handle = 0;
    uint32_t resource_handle = 0;
    uint32_t resource_type = 0;
    uint64_t guest_address = 0;
    uint64_t size_bytes = 0;
    std::string name;
};

struct AgcRegisteredShader {
    uint64_t shader_struct_addr = 0;
    uint64_t header_addr = 0;
    uint64_t code_addr = 0;
    uint64_t isa_hash = 0;
    uint64_t vk_shader_module = 0;
    uint32_t instruction_count = 0;
    uint32_t salu_count = 0;
    uint32_t valu_count = 0;
    uint32_t vmem_count = 0;
    uint32_t smem_count = 0;
    uint32_t branch_count = 0;
    uint32_t spirv_bytes = 0;
    bool     spirv_verified_on_gpu = false;
};

struct AgcDriverStats {
    uint64_t init_calls = 0;
    uint64_t owners_registered = 0;
    uint64_t resources_registered = 0;
    uint64_t shaders_created = 0;
    uint64_t shaders_compiled_to_spirv = 0;
    uint64_t unique_cached_vk_modules = 0;
    uint64_t total_spirv_bytes_generated = 0;
    uint64_t total_shader_instructions = 0;
    uint64_t dcb_packets_emitted = 0;
    uint64_t dcb_submissions = 0;
    uint64_t acb_submissions = 0;
    uint64_t sh_reg_writes = 0;
    uint64_t eop_fences_signaled = 0;
    uint64_t flips_scheduled = 0;
};

class AgcDriverHleManager {
public:
    static AgcDriverHleManager& Instance();

    bool Initialize();
    void Shutdown();

    // Central HLE dispatcher for libSceAgc (68 NIDs) and libSceAgcDriver (8 NIDs)
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

    // Emit a Type-3 PM4 packet directly into a guest DrawCommandBuffer / AsyncComputeCommandBuffer
    bool EmitPm4PacketToGuestCb(uint64_t guest_cb_addr, uint8_t opcode, const uint32_t* payload, uint16_t payload_dwords);

    // Submit a guest DCB/ACB command buffer stream to AgcPm4Backend & VulkanHostBackend
    uint32_t SubmitGuestCommandBuffer(const uint32_t* cmd_dwords, size_t dword_count, bool is_async_compute = false);

    const AgcDriverStats& GetStats() const { return stats_; }
    size_t GetRegisteredResourceCount() const { return resources_.size(); }
    size_t GetRegisteredShaderCount() const { return shaders_.size(); }
    size_t CompileAndVerifyRegisteredShadersOnGpu(size_t max_compile_batch = 64);
    void PrintLiveAgcBreakdown() const;
    void PrintShaderAndResourceCatalog(size_t max_sample_shaders = 6) const;

private:
    AgcDriverHleManager() = default;

    static bool IsValidGuestPointer(uint64_t addr);

    mutable std::mutex mutex_;
    bool initialized_ = false;
    uint32_t next_owner_handle_ = 1;
    uint32_t next_resource_handle_ = 1;
    uint64_t active_index_buffer_addr_ = 0;
    uint32_t active_index_type_ = 0; // 0 = 16-bit, 1 = 32-bit
    uint32_t active_num_instances_ = 1;

    AgcDriverStats stats_{};
    std::vector<AgcRegisteredResource> resources_;
    std::vector<AgcRegisteredShader> shaders_;
    std::vector<std::string> live_markers_;
    std::unordered_map<std::string, uint64_t> fn_call_counts_;
    std::unordered_map<std::string, uint64_t> fn_last_rdi_;
};

} // namespace yotei::graphics
