#include "graphics/agc_driver_hle.h"
#include "graphics/pm4_decoder.h"
#include "graphics/rdna2_shader.h"
#include "graphics/video_out_hle.h"
#include "graphics/vk_backend.h"
#include "kernel/threads.h"
#include <cstring>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::graphics {

AgcDriverHleManager& AgcDriverHleManager::Instance() {
    static AgcDriverHleManager instance;
    return instance;
}

bool AgcDriverHleManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) return true;
    stats_ = {};
    resources_.clear();
    shaders_.clear();
    next_owner_handle_ = 1;
    next_resource_handle_ = 1;
    initialized_ = true;
    return true;
}

void AgcDriverHleManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    resources_.clear();
    shaders_.clear();
    initialized_ = false;
}

bool AgcDriverHleManager::IsValidGuestPointer(uint64_t addr) {
    if (addr < 0x100000ULL || addr > 0x7FFFFFFFFFFFULL) return false;
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
#endif
    return true;
}

bool AgcDriverHleManager::EmitPm4PacketToGuestCb(
    uint64_t guest_cb_addr,
    uint8_t opcode,
    const uint32_t* payload,
    uint16_t payload_dwords) {
    if (!IsValidGuestPointer(guest_cb_addr)) return false;

    auto* cb = reinterpret_cast<GuestAgcCommandBuffer*>(guest_cb_addr);
    uint64_t cur_addr = reinterpret_cast<uint64_t>(cb->cmd_cur);
    uint64_t end_addr = reinterpret_cast<uint64_t>(cb->cmd_end);

    size_t needed_bytes = static_cast<size_t>(payload_dwords + 1) * sizeof(uint32_t);
    if (!IsValidGuestPointer(cur_addr) || (end_addr > cur_addr && (cur_addr + needed_bytes > end_addr))) {
        return false;
    }

    uint16_t count_minus_one = (payload_dwords > 0) ? (payload_dwords - 1) : 0;
    uint32_t header = (3U << 30) | (static_cast<uint32_t>(count_minus_one & 0x3FFF) << 16) | (static_cast<uint32_t>(opcode) << 8);
    cb->cmd_cur[0] = header;
    for (uint16_t i = 0; i < payload_dwords; ++i) {
        cb->cmd_cur[1 + i] = payload ? payload[i] : 0;
    }
    cb->cmd_cur += (1 + payload_dwords);
    ++stats_.dcb_packets_emitted;
    return true;
}

uint32_t AgcDriverHleManager::SubmitGuestCommandBuffer(
    const uint32_t* cmd_dwords,
    size_t dword_count,
    bool is_async_compute) {
    if (!cmd_dwords || dword_count == 0 || !IsValidGuestPointer(reinterpret_cast<uint64_t>(cmd_dwords))) {
        return 0;
    }
    if (is_async_compute) {
        ++stats_.acb_submissions;
    } else {
        ++stats_.dcb_submissions;
    }

    auto pkts = AgcPm4Backend::Instance().DecodeCommandStream(cmd_dwords, dword_count);
    return static_cast<uint32_t>(pkts.size());
}

bool AgcDriverHleManager::DispatchNid(
    const std::string& library,
    const std::string& nid,
    const std::string& resolved_name,
    uint64_t rdi,
    uint64_t rsi,
    uint64_t rdx,
    uint64_t rcx,
    uint64_t r8,
    uint64_t r9,
    uint64_t* out_ret) {
    if (library != "libSceAgc" && library != "libSceAgcDriver") {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        initialized_ = true;
    }

    std::string fn_key = library + "::" + resolved_name + " (" + nid + ")";
    fn_call_counts_[fn_key]++;
    fn_last_rdi_[fn_key] = rdi;

    // -------------------------------------------------------------------------
    // 1. Core AGC Initialization & Mode Queries
    // -------------------------------------------------------------------------
    if (nid == "23LRUSvYu1M" || resolved_name == "Gen5::AgcInit" || resolved_name == "sceAgcInit") {
        ++stats_.init_calls;
        if (IsValidGuestPointer(rdi)) {
            *reinterpret_cast<uint32_t*>(rdi) = 0;
        }
        *out_ret = 0; // SCE_OK
        return true;
    }
    if (nid == "BfBDZGbti7A" || nid == "dbOlWdppb4o" ||
        resolved_name == "sceAgcGetIsTrinityMode" || resolved_name == "Gen5::AgcGetIsTrinityMode") {
        *out_ret = 0; // Base PS5 Prospero mode
        return true;
    }
    if (nid == "2JtWUUiYBXs" || nid == "wRbq6ZjNop4" ||
        resolved_name == "sceAgcGetRegisterDefaults2" ||
        resolved_name == "sceAgcGetRegisterDefaults2Internal" ||
        resolved_name == "Gen5::AgcGetRegisterDefaults2" ||
        resolved_name == "Gen5::AgcGetRegisterDefaults2Internal") {
        // Returns a valid pointer to a static AGC default register table (prevents [RAX+0x38] null dereference in Agc::Core::initialize)
        alignas(64) static uint8_t s_agc_default_register_table[4096] = {};
        if (IsValidGuestPointer(rdi) && rsi > 0 && rsi <= 0x10000) {
            std::memset(reinterpret_cast<void*>(rdi), 0, static_cast<size_t>(rsi));
        }
        *out_ret = reinterpret_cast<uint64_t>(&s_agc_default_register_table[0]);
        return true;
    }
    if (nid == "h9z6+0hEydk" || nid == "qj7QZpgr9Uw" ||
        resolved_name == "sceAgcSuspendPoint" || resolved_name == "Gen5::AgcSuspendPoint") {
        *out_ret = 0;
        return true;
    }
    if (nid == "NKIzURsgV7I" || resolved_name == "sceAgcGetGsOversubscription") {
        *out_ret = 0;
        return true;
    }

    // -------------------------------------------------------------------------
    // 2. Packet Size Queries (*GetSize)
    // -------------------------------------------------------------------------
    if (resolved_name.find("GetSize") != std::string::npos ||
        nid == "Abendgtz+3o" || nid == "VEGu4dixjUg" || nid == "bxGoVxpdSPQ" || nid == "t7PlZ9nt5Lc") {
        // Return a safe PM4 command reservation size in dwords/bytes (16 bytes = 4 dwords)
        *out_ret = 16;
        return true;
    }

    // -------------------------------------------------------------------------
    // 3. libSceAgcDriver Resource & Owner Registration
    // -------------------------------------------------------------------------
    if (nid == "X-Nm5KLREeg" || resolved_name == "sceAgcDriverRegisterOwner") {
        // sceAgcDriverRegisterOwner(uint32_t* out_owner_handle, const char* owner_name)
        uint32_t handle = next_owner_handle_++;
        if (IsValidGuestPointer(rdi)) {
            *reinterpret_cast<uint32_t*>(rdi) = handle;
        }
        ++stats_.owners_registered;
        *out_ret = 0;
        return true;
    }
    if (nid == "W5z4eZrjEas" || resolved_name == "sceAgcDriverRegisterResource") {
        // sceAgcDriverRegisterResource(uint32_t* out_res_handle, uint32_t owner_handle, const void* info, ...)
        uint32_t res_handle = next_resource_handle_++;
        if (IsValidGuestPointer(rdi)) {
            *reinterpret_cast<uint32_t*>(rdi) = res_handle;
        }
        AgcRegisteredResource res{};
        res.owner_handle = static_cast<uint32_t>(rsi);
        res.resource_handle = res_handle;
        res.guest_address = rdx;
        res.size_bytes = rcx;
        if (IsValidGuestPointer(r8)) {
            res.name = reinterpret_cast<const char*>(r8);
        }
        resources_.push_back(std::move(res));
        ++stats_.resources_registered;
        *out_ret = 0;
        return true;
    }
    if (nid == "w2rJhmD+dsE" || resolved_name == "sceAgcDriverAddEqEvent") {
        // sceAgcDriverAddEqEvent(SceKernelEqueue eq, SceAgcCoreEqEventType type, void* udata)
        yotei::kernel::ThreadManager::Instance().EqueueAddEvent(rdi, (rsi != 0) ? rsi : 1, -14 /* EVFILT_GRAPHICS_CORE */, rdx);
        *out_ret = 0;
        return true;
    }
    if (nid == "MM4IZSEYytQ" || nid == "XlNp7jzGiPo" ||
        resolved_name == "sceAgcDriverSetHsOffchipParam" ||
        resolved_name == "sceAgcDriverSetTFRing") {
        *out_ret = 0;
        return true;
    }

    // -------------------------------------------------------------------------
    // 4. Shader & State Creation (sceAgcCreateShader / sceAgcCreatePrimState)
    // -------------------------------------------------------------------------
    if (nid == "f3dg2CSgRKY" || resolved_name == "sceAgcCreateShader") {
        // sceAgcCreateShader(SceAgcShader** out_shader, void* header, const void* code)
        AgcRegisteredShader sh{};
        sh.shader_struct_addr = rdi;
        sh.header_addr = rsi;
        sh.code_addr = rdx;

        if (IsValidGuestPointer(rdi) && IsValidGuestPointer(rsi)) {
            *reinterpret_cast<uint64_t*>(rdi) = rsi;
            *reinterpret_cast<uint64_t*>(rsi) = rdx;
        }
        // Probe rdx (or rsi if rdx is not code) for RDNA2 ISA instruction stream
        uint64_t candidate_code = IsValidGuestPointer(rdx) ? rdx : (IsValidGuestPointer(rsi) ? rsi : 0);
        if (candidate_code != 0) {
            sh.code_addr = candidate_code;
            auto analysis = Rdna2ShaderAnalyzer::AnalyzeIsa(reinterpret_cast<const uint32_t*>(candidate_code), 64, 4);
            sh.isa_hash = analysis.code_hash;
            sh.instruction_count = analysis.total_instructions;
            sh.salu_count = analysis.salu_count;
            sh.valu_count = analysis.valu_count;
            sh.vmem_count = analysis.vmem_mimg_count;
            sh.smem_count = analysis.smem_count;
            sh.branch_count = analysis.branch_count;
            stats_.total_shader_instructions += analysis.total_instructions;
        }
        shaders_.push_back(sh);
        ++stats_.shaders_created;
        *out_ret = 0;
        return true;
    }
    if (nid == "D9sr1xGUriE" || nid == "V++UgBtQhn0" ||
        resolved_name == "sceAgcCreatePrimState" ||
        resolved_name == "Gen5::AgcCreateInterpolantMapping") {
        *out_ret = 0;
        return true;
    }

    // -------------------------------------------------------------------------
    // 5. Debug Markers (PushMarker / PopMarker / SetMarker)
    // -------------------------------------------------------------------------
    if (nid == "+kSrjIVxKFE" || nid == "cpCILPya5Zk" ||
        resolved_name == "sceAgcDcbPushMarker" || resolved_name == "sceAgcAcbPushMarker" ||
        resolved_name == "Gen5::AgcDcbPushMarker" || resolved_name == "Gen5::AgcAcbPushMarker") {
        if (IsValidGuestPointer(rsi)) {
            const char* marker_str = reinterpret_cast<const char*>(rsi);
            uint32_t nop_payload[8] = { 0x68757053U }; // 'Spuh' marker tag
            size_t len = std::min<size_t>(std::strlen(marker_str), 24);
            std::memcpy(&nop_payload[1], marker_str, len);
            uint16_t words = static_cast<uint16_t>(1 + ((len + 3) / 4));
            EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_NOP), nop_payload, words);
        }
        *out_ret = 0;
        return true;
    }
    if (nid == "H7uZqCoNuWk" || nid == "6mFxkVqdmbQ" ||
        resolved_name == "sceAgcDcbPopMarker" || resolved_name == "sceAgcAcbPopMarker" ||
        resolved_name == "Gen5::AgcDcbPopMarker" || resolved_name == "Gen5::AgcAcbPopMarker") {
        uint32_t nop_payload[1] = { 0 };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_NOP), nop_payload, 1);
        *out_ret = 0;
        return true;
    }

    // -------------------------------------------------------------------------
    // 6. End-Of-Pipe (EOP) WriteData / ReleaseMem / WaitRegMem Synchronization
    // -------------------------------------------------------------------------
    if (nid == "i1jyy49AjXU" || nid == "eZ4+17OQz4Q" ||
        resolved_name == "sceAgcDcbWriteData" || resolved_name == "sceAgcAcbWriteData") {
        // Immediately write payload to destination guest memory if valid so CPU fence polling succeeds
        if (IsValidGuestPointer(rdx)) {
            if (IsValidGuestPointer(rcx) && r8 > 0 && r8 <= 64) {
                std::memcpy(reinterpret_cast<void*>(rdx), reinterpret_cast<const void*>(rcx), static_cast<size_t>(r8));
            } else {
                *reinterpret_cast<uint64_t*>(rdx) = rcx;
            }
            ++stats_.eop_fences_signaled;
        }
        uint32_t wd_payload[4] = {
            static_cast<uint32_t>(rsi),
            static_cast<uint32_t>(rdx & 0xFFFFFFFFULL),
            static_cast<uint32_t>(rdx >> 32),
            static_cast<uint32_t>(rcx & 0xFFFFFFFFULL)
        };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_WRITE_DATA), wd_payload, 4);
        *out_ret = 0;
        return true;
    }
    if (nid == "wr23dPKyWc0" || nid == "aJf+j5yntiU" || nid == "cFazmnXpJOE" ||
        resolved_name == "sceAgcCbReleaseMem" ||
        resolved_name == "sceAgcDcbEventWrite" ||
        resolved_name == "sceAgcAcbEventWrite") {
        // Check if any argument is an EOP label pointer and signal it
        if (IsValidGuestPointer(rdx) && (rdx & 0x7) == 0) {
            *reinterpret_cast<uint64_t*>(rdx) = (rcx != 0) ? rcx : 1ULL;
            ++stats_.eop_fences_signaled;
        }
        uint32_t rel_payload[2] = { static_cast<uint32_t>(rsi), static_cast<uint32_t>(rcx) };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_RELEASE_MEM), rel_payload, 2);
        *out_ret = 0;
        return true;
    }
    if (nid == "VmW0Tdpy420" || nid == "htn36gPnBk4" || nid == "MWiElSNE8j8" ||
        resolved_name == "sceAgcDcbWaitRegMem" ||
        resolved_name == "sceAgcAcbWaitRegMem" ||
        resolved_name == "sceAgcDcbWaitUntilSafeForRendering") {
        // Ensure watched memory holds expected reference value so guest never deadlocks
        if (IsValidGuestPointer(rdx) && (rdx & 0x3) == 0) {
            *reinterpret_cast<uint32_t*>(rdx) = static_cast<uint32_t>(rcx);
        }
        *out_ret = 0;
        return true;
    }

    // -------------------------------------------------------------------------
    // 7. Index Buffer, Registers & Draw / Compute Dispatch Recording
    // -------------------------------------------------------------------------
    if (nid == "l4fM9K-Lyks" || resolved_name == "sceAgcDcbSetIndexBuffer") {
        active_index_buffer_addr_ = rsi;
        uint32_t ib_payload[2] = {
            static_cast<uint32_t>(rsi & 0xFFFFFFFFULL),
            static_cast<uint32_t>(rsi >> 32)
        };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_INDEX_BASE), ib_payload, 2);
        *out_ret = 0;
        return true;
    }
    if (nid == "-KRzWekV120" || resolved_name == "sceAgcDcbSetIndexSize_0600") {
        active_index_type_ = static_cast<uint32_t>(rsi);
        uint32_t it_payload[1] = { active_index_type_ };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_INDEX_TYPE), it_payload, 1);
        *out_ret = 0;
        return true;
    }
    if (nid == "8N2tmT3jmC8" || resolved_name == "sceAgcDcbSetIndexCount") {
        uint32_t ic_payload[1] = { static_cast<uint32_t>(rsi) };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_INDEX_BUFFER_SIZE), ic_payload, 1);
        *out_ret = 0;
        return true;
    }
    if (nid == "tSBxhAPyytQ" || resolved_name == "sceAgcDcbSetNumInstances") {
        active_num_instances_ = (rsi > 0) ? static_cast<uint32_t>(rsi) : 1U;
        uint32_t ni_payload[1] = { active_num_instances_ };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_NUM_INSTANCES), ni_payload, 1);
        *out_ret = 0;
        return true;
    }
    if (nid == "q88lQ+GP5Yk" || resolved_name == "sceAgcDcbDrawIndex") {
        // sceAgcDcbDrawIndex(dcb, indexCount, indexAddr, ...)
        uint32_t idx_count = static_cast<uint32_t>(rsi);
        uint64_t ib_addr = (rdx != 0) ? rdx : active_index_buffer_addr_;
        uint32_t di_payload[5] = {
            idx_count,
            static_cast<uint32_t>(ib_addr & 0xFFFFFFFFULL),
            static_cast<uint32_t>(ib_addr >> 32),
            idx_count,
            0x2U // DI_SRC_SEL_DMA
        };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_DRAW_INDEX_2), di_payload, 5);
        *out_ret = 0;
        return true;
    }
    if (nid == "Yw0jKSqop+E" || resolved_name == "sceAgcDcbDrawIndexAuto") {
        uint32_t vtx_count = static_cast<uint32_t>(rsi);
        uint32_t da_payload[2] = { vtx_count, 0x2U };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_DRAW_INDEX_AUTO), da_payload, 2);
        *out_ret = 0;
        return true;
    }
    if (nid == "t1vNu082-jM" || nid == "ypVBz4uPKcQ" || nid == "1q1titRBL6o" ||
        resolved_name == "sceAgcDcbDrawIndexIndirect" ||
        resolved_name == "sceAgcDcbDrawIndexIndirectMulti" ||
        resolved_name == "sceAgcDcbDrawIndirect") {
        uint32_t ind_payload[2] = { static_cast<uint32_t>(rsi), static_cast<uint32_t>(rdx) };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_DRAW_INDEX_INDIRECT), ind_payload, 2);
        *out_ret = 0;
        return true;
    }
    if (nid == "k3GhuSNmBLU" || resolved_name == "sceAgcCbDispatch" || resolved_name == "Gen5::AgcCbDispatch") {
        // sceAgcCbDispatch(cb, gx, gy, gz, ...)
        uint32_t dp_payload[4] = {
            static_cast<uint32_t>(rsi > 0 ? rsi : 1),
            static_cast<uint32_t>(rdx > 0 ? rdx : 1),
            static_cast<uint32_t>(rcx > 0 ? rcx : 1),
            1U
        };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_DISPATCH_DIRECT), dp_payload, 4);
        *out_ret = 0;
        return true;
    }
    if (nid == "CtB+A9-VxO0" || nid == "j3EtxFkSIhQ" ||
        resolved_name == "sceAgcDcbDispatchIndirect" || resolved_name == "sceAgcAcbDispatchIndirect") {
        uint32_t dpi_payload[2] = { static_cast<uint32_t>(rsi), 1U };
        EmitPm4PacketToGuestCb(rdi, static_cast<uint8_t>(Pm4Opcode::IT_DISPATCH_INDIRECT), dpi_payload, 2);
        *out_ret = 0;
        return true;
    }

    // -------------------------------------------------------------------------
    // 8. Flip Command & Command Buffer Submission (libSceAgcDriver)
    // -------------------------------------------------------------------------
    if (nid == "YUeqkyT7mEQ" || resolved_name == "sceAgcDcbSetFlip" || resolved_name == "Gen5::AgcDcbSetFlip") {
        // sceAgcDcbSetFlip(dcb, videoOutHandle, bufferIndex, flipMode, flipArg)
        ++stats_.flips_scheduled;
        VideoOutHleManager::Instance().SubmitFlip(
            static_cast<int32_t>(rsi > 0 ? rsi : 1),
            static_cast<int32_t>(rdx),
            static_cast<int32_t>(rcx),
            static_cast<int64_t>(r8));
        *out_ret = 0;
        return true;
    }
    if (nid == "UglJIZjGssM" || nid == "AhGvpITrf4M" ||
        resolved_name == "sceAgcDriverSubmitDcb" ||
        resolved_name == "Gen5Driver::AgcDriverSubmitDcb" ||
        resolved_name == "Gen5Driver::AgcDriverSubmitMultiCommandBuffers") {
        // Supports both direct (cmd_ptr, size_bytes) and array-of-pointers submission
        if (IsValidGuestPointer(rdi) && rsi > 0 && rsi <= 0x100000) {
            SubmitGuestCommandBuffer(reinterpret_cast<const uint32_t*>(rdi), static_cast<size_t>(rsi / 4), false);
        } else if (IsValidGuestPointer(rsi) && rdx > 0 && rdx <= 0x100000) {
            SubmitGuestCommandBuffer(reinterpret_cast<const uint32_t*>(rsi), static_cast<size_t>(rdx / 4), false);
        } else {
            ++stats_.dcb_submissions;
        }
        *out_ret = 0;
        return true;
    }
    if (nid == "gSRnr79F8tQ" ||
        resolved_name == "sceAgcDriverSubmitAcb" ||
        resolved_name == "Gen5Driver::AgcDriverSubmitMultiAcbs") {
        if (IsValidGuestPointer(rdi) && rsi > 0 && rsi <= 0x100000) {
            SubmitGuestCommandBuffer(reinterpret_cast<const uint32_t*>(rdi), static_cast<size_t>(rsi / 4), true);
        } else {
            ++stats_.acb_submissions;
        }
        *out_ret = 0;
        return true;
    }

    // Default handler for all remaining libSceAgc register/patch helpers
    (void)r9;
    *out_ret = 0;
    return true;
}

void AgcDriverHleManager::PrintLiveAgcBreakdown() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << "[+] Live libSceAgc & libSceAgcDriver Function Call Breakdown ("
              << fn_call_counts_.size() << " distinct AGC functions invoked):\n";
    for (const auto& [key, cnt] : fn_call_counts_) {
        auto it_rdi = fn_last_rdi_.find(key);
        uint64_t last_arg = (it_rdi != fn_last_rdi_.end()) ? it_rdi->second : 0;
        std::cout << "    " << std::setw(54) << std::left << key
                  << " : " << std::setw(5) << cnt << " calls | last_rdi=0x"
                  << std::hex << last_arg << std::dec << "\n";
    }
}

size_t AgcDriverHleManager::CompileAndVerifyRegisteredShadersOnGpu(size_t max_compile_batch) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& vk = VulkanHostBackend::Instance();
    if (!vk.IsInitialized()) return 0;

    size_t compiled_ok = 0;
    size_t attempted = 0;
    for (auto& sh : shaders_) {
        if (attempted >= max_compile_batch) break;
        if (!IsValidGuestPointer(sh.code_addr)) continue;
        ++attempted;
        auto analysis = Rdna2ShaderAnalyzer::AnalyzeIsa(reinterpret_cast<const uint32_t*>(sh.code_addr), 64, 16);
        auto spirv = Rdna2ShaderAnalyzer::TranslateRdna2ToSpirv(analysis, 64, 1, 1);
        sh.spirv_bytes = static_cast<uint32_t>(spirv.size() * sizeof(uint32_t));
        if (vk.VerifySpirvShaderModule(spirv)) {
            sh.spirv_verified_on_gpu = true;
            ++compiled_ok;
        }
    }
    stats_.shaders_compiled_to_spirv = compiled_ok;
    return compiled_ok;
}

void AgcDriverHleManager::PrintShaderAndResourceCatalog(size_t max_sample_shaders) const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total_salu = 0, total_valu = 0, total_vmem = 0, total_smem = 0, total_branches = 0;
    for (const auto& sh : shaders_) {
        total_salu += sh.salu_count;
        total_valu += sh.valu_count;
        total_vmem += sh.vmem_count;
        total_smem += sh.smem_count;
        total_branches += sh.branch_count;
    }

    std::cout << "[+] Live Registered AGC Shader & Resource Catalog (Milestones 19 & 24):\n"
              << "    Total Shaders Registered   : " << shaders_.size()
              << " (" << stats_.total_shader_instructions << " RDNA2 instructions decoded | SALU="
              << total_salu << " VALU=" << total_valu << " VMEM=" << total_vmem
              << " SMEM/SRT=" << total_smem << " Branches=" << total_branches << ")\n"
              << "    SPIR-V 1.6 GPU Compiled    : " << stats_.shaders_compiled_to_spirv
              << " live game shaders compiled to VkShaderModule on GPU\n"
              << "    Total Resources Registered : " << resources_.size()
              << " | Owners: " << stats_.owners_registered << "\n";

    size_t shown = 0;
    for (size_t i = 0; i < shaders_.size() && shown < max_sample_shaders; ++i) {
        const auto& sh = shaders_[i];
        if (sh.isa_hash == 0) continue;
        std::cout << "      Shader[#" << std::setw(3) << i << "] CodeAddr=0x" << std::hex << sh.code_addr
                  << " Hash=0x" << sh.isa_hash << std::dec
                  << " | Insns=" << sh.instruction_count
                  << " (SALU=" << sh.salu_count << " VALU=" << sh.valu_count
                  << " VMEM=" << sh.vmem_count << " SRT=" << sh.smem_count
                  << " BR=" << sh.branch_count << ")"
                  << " | SPIR-V=" << sh.spirv_bytes << "B ("
                  << (sh.spirv_verified_on_gpu ? "VkShaderModule OK" : "pending") << ")\n";
        ++shown;
    }
}

} // namespace yotei::graphics
