#include "graphics/pm4_decoder.h"
#include "graphics/rdna2_shader.h"
#include "graphics/vk_backend.h"
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace yotei::graphics {

AgcPm4Backend& AgcPm4Backend::Instance() {
    static AgcPm4Backend instance;
    return instance;
}

const char* AgcPm4Backend::GetOpcodeName(uint8_t op) {
    switch (static_cast<Pm4Opcode>(op)) {
        case Pm4Opcode::IT_NOP:                  return "IT_NOP";
        case Pm4Opcode::IT_SET_BASE:             return "IT_SET_BASE";
        case Pm4Opcode::IT_INDEX_BUFFER_SIZE:    return "IT_INDEX_BUFFER_SIZE";
        case Pm4Opcode::IT_DISPATCH_DIRECT:      return "IT_DISPATCH_DIRECT";
        case Pm4Opcode::IT_DISPATCH_INDIRECT:    return "IT_DISPATCH_INDIRECT";
        case Pm4Opcode::IT_SET_PREDICATION:      return "IT_SET_PREDICATION";
        case Pm4Opcode::IT_COND_EXEC:            return "IT_COND_EXEC";
        case Pm4Opcode::IT_DRAW_INDIRECT:        return "IT_DRAW_INDIRECT";
        case Pm4Opcode::IT_DRAW_INDEX_INDIRECT:  return "IT_DRAW_INDEX_INDIRECT";
        case Pm4Opcode::IT_INDEX_BASE:           return "IT_INDEX_BASE";
        case Pm4Opcode::IT_DRAW_INDEX_2:         return "IT_DRAW_INDEX_2";
        case Pm4Opcode::IT_INDEX_TYPE:           return "IT_INDEX_TYPE";
        case Pm4Opcode::IT_DRAW_INDIRECT_MULTI:  return "IT_DRAW_INDIRECT_MULTI";
        case Pm4Opcode::IT_DRAW_INDEX_AUTO:      return "IT_DRAW_INDEX_AUTO";
        case Pm4Opcode::IT_NUM_INSTANCES:        return "IT_NUM_INSTANCES";
        case Pm4Opcode::IT_DRAW_INDEX_OFFSET_2:  return "IT_DRAW_INDEX_OFFSET_2";
        case Pm4Opcode::IT_WRITE_DATA:           return "IT_WRITE_DATA";
        case Pm4Opcode::IT_WAIT_REG_MEM:         return "IT_WAIT_REG_MEM";
        case Pm4Opcode::IT_INDIRECT_BUFFER:      return "IT_INDIRECT_BUFFER";
        case Pm4Opcode::IT_COPY_DATA:            return "IT_COPY_DATA";
        case Pm4Opcode::IT_EVENT_WRITE:          return "IT_EVENT_WRITE";
        case Pm4Opcode::IT_EVENT_WRITE_EOP:      return "IT_EVENT_WRITE_EOP";
        case Pm4Opcode::IT_RELEASE_MEM:          return "IT_RELEASE_MEM";
        case Pm4Opcode::IT_DMA_DATA:             return "IT_DMA_DATA";
        case Pm4Opcode::IT_ACQUIRE_MEM:          return "IT_ACQUIRE_MEM";
        case Pm4Opcode::IT_REWIND:               return "IT_REWIND";
        case Pm4Opcode::IT_SET_CONTEXT_REG:      return "IT_SET_CONTEXT_REG";
        case Pm4Opcode::IT_SET_SH_REG:           return "IT_SET_SH_REG";
        case Pm4Opcode::IT_SET_UCONFIG_REG:      return "IT_SET_UCONFIG_REG";
        default:                                 return "IT_UNKNOWN_PM4";
    }
}

std::vector<DecodedPm4Packet> AgcPm4Backend::DecodeCommandStream(
    const uint32_t* dwords,
    size_t dword_count) {
    std::vector<DecodedPm4Packet> out;
    if (!dwords || dword_count == 0) return out;

    size_t idx = 0;
    while (idx < dword_count) {
        uint32_t hdr = dwords[idx];
        uint32_t pkt_type = (hdr >> 30) & 0x3;
        if (pkt_type == 2) {
            // Type-2 filler packet (1 dword)
            ++idx;
            continue;
        }
        if (pkt_type != 3) {
            // Non-Type-3 packet or end of valid stream
            break;
        }

        uint8_t opcode = static_cast<uint8_t>((hdr >> 8) & 0xFF);
        uint16_t body_dwords = static_cast<uint16_t>(((hdr >> 16) & 0x3FFF) + 1);
        if (idx + 1 + body_dwords > dword_count) {
            break;
        }

        const uint32_t* body = dwords + idx + 1;
        std::ostringstream detail;

        switch (static_cast<Pm4Opcode>(opcode)) {
            case Pm4Opcode::IT_SET_CONTEXT_REG: {
                if (body_dwords >= 2) {
                    uint32_t reg_off = body[0] & 0xFFFF;
                    for (uint16_t r = 1; r < body_dwords; ++r) {
                        context_regs_[0xA000 + reg_off + (r - 1)] = body[r];
                    }
                    detail << "reg=0x" << std::hex << (0xA000 + reg_off)
                           << " count=" << std::dec << (body_dwords - 1);
                }
                break;
            }
            case Pm4Opcode::IT_SET_SH_REG: {
                if (body_dwords >= 2) {
                    uint32_t reg_off = body[0] & 0xFFFF;
                    for (uint16_t r = 1; r < body_dwords; ++r) {
                        sh_regs_[0x2C00 + reg_off + (r - 1)] = body[r];
                    }
                    detail << "reg=0x" << std::hex << (0x2C00 + reg_off)
                           << " count=" << std::dec << (body_dwords - 1);
                }
                break;
            }
            case Pm4Opcode::IT_SET_UCONFIG_REG: {
                if (body_dwords >= 2) {
                    uint32_t reg_off = body[0] & 0xFFFF;
                    for (uint16_t r = 1; r < body_dwords; ++r) {
                        uconfig_regs_[0xC000 + reg_off + (r - 1)] = body[r];
                    }
                    detail << "reg=0x" << std::hex << (0xC000 + reg_off)
                           << " count=" << std::dec << (body_dwords - 1);
                }
                break;
            }
            case Pm4Opcode::IT_DISPATCH_DIRECT: {
                if (body_dwords >= 3) {
                    uint32_t gx = body[0];
                    uint32_t gy = body[1];
                    uint32_t gz = body[2];
                    detail << "groups=(" << gx << ", " << gy << ", " << gz << ")";
                    ++stats_.dispatches;

                    // If Vulkan host backend is initialized, dispatch to host GPU
                    auto& vk = VulkanHostBackend::Instance();
                    if (vk.IsInitialized()) {
                        auto spirv = Rdna2ShaderAnalyzer::EmitMinimalSpirvCompute(64, 1, 1);
                        vk.ExecuteCompute(spirv, (gx > 0 ? gx : 1), (gy > 0 ? gy : 1), (gz > 0 ? gz : 1));
                    }
                }
                break;
            }
            case Pm4Opcode::IT_DISPATCH_INDIRECT: {
                ++stats_.dispatches;
                if (body_dwords >= 1) {
                    detail << "data_offset=0x" << std::hex << body[0] << std::dec;
                }
                break;
            }
            case Pm4Opcode::IT_DRAW_INDEX_2:
            case Pm4Opcode::IT_DRAW_INDEX_AUTO:
            case Pm4Opcode::IT_DRAW_INDEX_INDIRECT:
            case Pm4Opcode::IT_DRAW_INDIRECT_MULTI:
            case Pm4Opcode::IT_DRAW_INDEX_OFFSET_2: {
                ++stats_.draw_calls;
                if (body_dwords >= 1) {
                    detail << "arg0=0x" << std::hex << body[0] << std::dec;
                }
                break;
            }
            case Pm4Opcode::IT_NOP: {
                // Sony AGC encodes debug markers inside IT_NOP payloads
                if (body_dwords >= 2) {
                    const char* txt = reinterpret_cast<const char*>(body + 1);
                    size_t max_chars = (body_dwords - 1) * 4;
                    size_t len = 0;
                    while (len < max_chars && txt[len] >= 32 && txt[len] < 127) ++len;
                    if (len >= 3) {
                        std::string marker(txt, len);
                        detail << "marker=\"" << marker << "\"";
                        stats_.marker_history.push_back(marker);
                    }
                }
                break;
            }
            default:
                break;
        }

        out.push_back({opcode, body_dwords, GetOpcodeName(opcode), detail.str()});
        idx += 1 + body_dwords;
    }
    return out;
}

bool AgcPm4Backend::DispatchNid(
    const std::string& library,
    const std::string& nid,
    const std::string& resolved_name,
    uint64_t rdi,
    uint64_t rsi,
    uint64_t rdx,
    uint64_t rcx,
    uint64_t /*r8*/,
    uint64_t /*r9*/,
    uint64_t* out_ret) {
    if (library != "libSceAgc" && library != "libSceAgcDriver" &&
        library != "libSceVideoOut" && library != "libSceVideoOutVrrStatus") {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // 1. All *GetSize functions in libSceAgc return the PM4 packet reservation size in dwords/bytes
    if (resolved_name.find("GetSize") != std::string::npos) {
        *out_ret = 32;
        return true;
    }
    if (resolved_name == "Gen5::AgcGetIsTrinityMode") {
        *out_ret = 0; // Standard PS5 Prospero
        return true;
    }
    if (resolved_name == "Gen5::AgcDriverGetResourceRegistrationMaxNameLength") {
        *out_ret = 64;
        return true;
    }
    if (resolved_name == "Gen5::AgcInit" || nid == "23LRUSvYu1M") {
        if (rdi != 0 && rdi >= 0x100000ULL) {
            *reinterpret_cast<uint32_t*>(rdi) = 0;
        }
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Gen5::AgcGetRegisterDefaults2" ||
        resolved_name == "Gen5::AgcGetRegisterDefaults2Internal") {
        *out_ret = 0;
        return true;
    }

    // 2. Debug Markers pushed by the engine (e.g. "Frame>Deferred", "CS Cloth", "FSR3>FSR3-ACCUMULATE")
    if (resolved_name == "Gen5::AgcDcbPushMarker" ||
        resolved_name == "Gen5::AgcAcbPushMarker" ||
        resolved_name == "Gen5::AgcDcbSetMarker" ||
        resolved_name == "Gen5::AgcAcbSetMarker") {
        if (rsi != 0 && rsi >= 0x100000ULL) {
            std::string marker(reinterpret_cast<const char*>(rsi));
            stats_.active_markers.push_back(marker);
            stats_.marker_history.push_back(marker);
        }
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Gen5::AgcDcbPopMarker" ||
        resolved_name == "Gen5::AgcAcbPopMarker") {
        if (!stats_.active_markers.empty()) {
            stats_.active_markers.pop_back();
        }
        *out_ret = 0;
        return true;
    }

    // 3. Draw & Compute Dispatch recording via libSceAgc helpers
    if (resolved_name == "Gen5::AgcCbDispatch" ||
        resolved_name == "Gen5::AgcAcbDispatchIndirect") {
        ++stats_.dispatches;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Gen5::AgcDcbDrawIndexIndirect" ||
        resolved_name == "Gen5::AgcDcbDrawIndexIndirectMulti" ||
        resolved_name == "Gen5::AgcDcbDrawIndirectMulti") {
        ++stats_.draw_calls;
        *out_ret = 0;
        return true;
    }

    // 4. Command Buffer Submission (libSceAgcDriver)
    if (resolved_name == "Gen5Driver::AgcDriverSubmitDcb" ||
        resolved_name == "Gen5Driver::AgcDriverSubmitMultiCommandBuffers") {
        ++stats_.dcb_submissions;
        if (rsi != 0 && rdx > 0 && rdx <= 0x100000) {
            DecodeCommandStream(reinterpret_cast<const uint32_t*>(rsi), static_cast<size_t>(rdx / 4));
        }
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Gen5Driver::AgcDriverSubmitMultiAcbs") {
        ++stats_.acb_submissions;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "Gen5::AgcDcbSetFlip" ||
        resolved_name == "VideoOut::VideoOutSubmitFlip") {
        ++stats_.flips;
        *out_ret = 0;
        return true;
    }

    // 5. VideoOut display port & flip status
    if (resolved_name == "sceVideoOutOpen") {
        *out_ret = 1; // handle 1
        return true;
    }
    if (resolved_name == "VideoOut::VideoOutIsOutputSupported") {
        *out_ret = 1;
        return true;
    }
    if (resolved_name == "VideoOut::VideoOutGetOutputStatus") {
        if (rsi != 0) *reinterpret_cast<uint64_t*>(rsi) = 1;
        *out_ret = 0;
        return true;
    }
    if (resolved_name == "VideoOut::VideoOutGetFlipStatus") {
        if (rsi != 0) {
            std::memset(reinterpret_cast<void*>(rsi), 0, 32);
            *reinterpret_cast<uint64_t*>(rsi) = stats_.flips;
        }
        *out_ret = 0;
        return true;
    }

    // Default for all other AGC / AgcDriver / VideoOut functions
    (void)rcx;
    *out_ret = 0;
    return true;
}

} // namespace yotei::graphics
