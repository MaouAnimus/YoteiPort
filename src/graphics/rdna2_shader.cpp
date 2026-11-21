#include "graphics/rdna2_shader.h"
#include <fstream>
#include <iomanip>
#include <sstream>

namespace yotei::graphics {

namespace {

uint64_t Fnv1a64(const void* data, size_t len) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

} // namespace

Rdna2ShaderAnalysis Rdna2ShaderAnalyzer::AnalyzeIsa(
    const uint32_t* code,
    size_t max_dwords,
    size_t max_disasm_lines) {
    Rdna2ShaderAnalysis out{};
    if (!code || max_dwords == 0) return out;

    size_t pc = 0;
    while (pc < max_dwords) {
        uint32_t w0 = code[pc];
        uint8_t step = 1;
        std::string mnem = "v_alu_op";
        std::ostringstream ops;

        // 1. Check SOPP (1011_1111_1 op[6:0] simm16[15:0]) -> (w0 >> 23) == 0x17F
        if ((w0 >> 23) == 0x17F) {
            ++out.salu_count;
            uint8_t op = static_cast<uint8_t>((w0 >> 16) & 0x7F);
            int16_t simm16 = static_cast<int16_t>(w0 & 0xFFFF);
            switch (op) {
                case 0x00: mnem = "s_nop"; ops << "0x" << std::hex << (w0 & 0xFFFF); break;
                case 0x01: mnem = "s_endpgm"; break;
                case 0x02: mnem = "s_branch"; ops << "rel=" << std::dec << simm16; break;
                case 0x04: mnem = "s_cbranch_scc0"; ops << "rel=" << std::dec << simm16; break;
                case 0x05: mnem = "s_cbranch_scc1"; ops << "rel=" << std::dec << simm16; break;
                case 0x06: mnem = "s_cbranch_vccz"; ops << "rel=" << std::dec << simm16; break;
                case 0x07: mnem = "s_cbranch_vccnz"; ops << "rel=" << std::dec << simm16; break;
                case 0x08: mnem = "s_cbranch_execz"; ops << "rel=" << std::dec << simm16; break;
                case 0x09: mnem = "s_cbranch_execnz"; ops << "rel=" << std::dec << simm16; break;
                case 0x0A: mnem = "s_barrier"; break;
                case 0x0C: mnem = "s_waitcnt"; ops << "0x" << std::hex << (w0 & 0xFFFF); break;
                case 0x20: mnem = "s_clause"; ops << "count=" << std::dec << ((w0 & 0x3F) + 1); break;
                case 0x21: mnem = "s_wait_idle"; break;
                default:   mnem = "s_sopp"; ops << "op=0x" << std::hex << int(op); break;
            }
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), 4, mnem, ops.str()
                });
            }
            ++out.total_instructions;
            if (op == 0x01) { // s_endpgm terminates the shader program
                out.terminated_by_endpgm = true;
                ++pc;
                break;
            }
        }
        // 2. Check SOP1 (1011_1110_1 sdst[6:0] op[7:0] ssrc0[7:0]) -> (w0 >> 23) == 0x17D
        else if ((w0 >> 23) == 0x17D) {
            ++out.salu_count;
            uint8_t sdst = static_cast<uint8_t>((w0 >> 16) & 0x7F);
            uint8_t op   = static_cast<uint8_t>((w0 >> 8) & 0xFF);
            uint8_t src0 = static_cast<uint8_t>(w0 & 0xFF);
            mnem = (op == 0x00) ? "s_mov_b32" : ((op == 0x01) ? "s_mov_b64" : "s_sop1");
            ops << "s" << int(sdst) << ", s" << int(src0);
            if (src0 == 0xFF && pc + 1 < max_dwords) {
                step = 2;
                ops << " [lit=0x" << std::hex << code[pc + 1] << "]";
            }
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), static_cast<uint8_t>(step * 4), mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        // 3. Check SOPK (1011_0 op[4:0] sdst[6:0] simm16[15:0]) -> (w0 >> 28) == 0xB
        else if ((w0 >> 28) == 0xB) {
            ++out.salu_count;
            uint8_t sdst = static_cast<uint8_t>((w0 >> 16) & 0x7F);
            mnem = "s_movk_i32";
            ops << "s" << int(sdst) << ", 0x" << std::hex << (w0 & 0xFFFF);
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), 4, mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        // 4. Check SOP2 (10 op[6:0] sdst[6:0] ssrc1[7:0] ssrc0[7:0]) -> (w0 >> 30) == 0x2
        else if ((w0 >> 30) == 0x2) {
            ++out.salu_count;
            uint8_t op   = static_cast<uint8_t>((w0 >> 23) & 0x7F);
            uint8_t sdst = static_cast<uint8_t>((w0 >> 16) & 0x7F);
            uint8_t src1 = static_cast<uint8_t>((w0 >> 8) & 0xFF);
            uint8_t src0 = static_cast<uint8_t>(w0 & 0xFF);
            switch (op) {
                case 0x00: mnem = "s_add_u32"; break;
                case 0x01: mnem = "s_sub_u32"; break;
                case 0x04: mnem = "s_addc_u32"; break;
                case 0x0E: mnem = "s_and_b32"; break;
                case 0x0F: mnem = "s_and_b64"; break;
                case 0x10: mnem = "s_or_b32"; break;
                case 0x1E: mnem = "s_lshl_b32"; break;
                case 0x20: mnem = "s_lshr_b32"; break;
                case 0x24: mnem = "s_mul_i32"; break;
                default:   mnem = "s_sop2"; break;
            }
            ops << "s" << int(sdst) << ", s" << int(src0) << ", s" << int(src1);
            if ((src0 == 0xFF || src1 == 0xFF) && pc + 1 < max_dwords) {
                step = 2;
                ops << " [lit=0x" << std::hex << code[pc + 1] << "]";
            }
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), static_cast<uint8_t>(step * 4), mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        // 5. Check SMEM (64-bit: 1111_01 op[7:0] sdata[6:0] sbase[5:0] ...) -> (w0 >> 26) == 0x3D
        else if ((w0 >> 26) == 0x3D && pc + 1 < max_dwords) {
            step = 2;
            ++out.smem_count;
            uint8_t op    = static_cast<uint8_t>((w0 >> 18) & 0xFF);
            uint8_t sdata = static_cast<uint8_t>((w0 >> 6) & 0x7F);
            uint8_t sbase = static_cast<uint8_t>((w0 & 0x3F) << 1);
            switch (op) {
                case 0x00: mnem = "s_load_dword"; break;
                case 0x01: mnem = "s_load_dwordx2"; break;
                case 0x02: mnem = "s_load_dwordx4"; break;
                case 0x03: mnem = "s_load_dwordx8"; break;
                case 0x04: mnem = "s_load_dwordx16"; break;
                default:   mnem = "s_smem_load"; break;
            }
            ops << "s" << int(sdata) << ", s[" << int(sbase) << ":" << int(sbase + 1)
                << "], 0x" << std::hex << (code[pc + 1] & 0x1FFFFF);
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), 8, mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        // 6. Check MIMG (64-bit: 1111_00 op[6:0] ... including IMAGE_BVH64_INTERSECT_RAY) -> (w0 >> 26) == 0x3C
        else if ((w0 >> 26) == 0x3C && pc + 1 < max_dwords) {
            step = 2;
            ++out.vmem_mimg_count;
            uint8_t op = static_cast<uint8_t>((w0 >> 18) & 0x7F);
            if (op == 0x66 || op == 0x67) {
                ++out.bvh_intersect_count;
                mnem = "image_bvh64_intersect_ray";
            } else if (op >= 0x20 && op <= 0x3F) {
                mnem = "image_sample";
            } else {
                mnem = "image_load_or_store";
            }
            uint8_t vdata = static_cast<uint8_t>((code[pc + 1] >> 8) & 0xFF);
            uint8_t vaddr = static_cast<uint8_t>(code[pc + 1] & 0xFF);
            ops << "v" << int(vdata) << ", v" << int(vaddr);
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), 8, mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        // 7. Check MUBUF / MTBUF / FLAT / GLOBAL (64-bit: 1110_00..1110_11 and 1101_11)
        else if (((w0 >> 26) >= 0x37 && (w0 >> 26) <= 0x3B) && pc + 1 < max_dwords) {
            step = 2;
            uint8_t top6 = static_cast<uint8_t>(w0 >> 26);
            if (top6 == 0x37) {
                ++out.ds_lds_count;
                mnem = "ds_read_or_write_b32";
            } else if (top6 == 0x3E) {
                ++out.exp_count;
                mnem = "exp";
            } else {
                ++out.vmem_mimg_count;
                mnem = (top6 == 0x38) ? "buffer_load_dword" : "global_load_or_store";
            }
            uint8_t vdata = static_cast<uint8_t>((code[pc + 1] >> 8) & 0xFF);
            uint8_t vaddr = static_cast<uint8_t>(code[pc + 1] & 0xFF);
            ops << "v" << int(vdata) << ", v" << int(vaddr);
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), 8, mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        // 8. Check VOP3 / VOP3P (64-bit: 1101_01 or 1100_11)
        else if (((w0 >> 26) == 0x35 || (w0 >> 26) == 0x33 || (w0 >> 26) == 0x34) && pc + 1 < max_dwords) {
            step = 2;
            ++out.valu_count;
            uint8_t vdst = static_cast<uint8_t>(w0 & 0xFF);
            uint16_t op  = static_cast<uint16_t>((w0 >> 16) & 0x3FF);
            mnem = "v_vop3_op";
            ops << "v" << int(vdst) << " (op=0x" << std::hex << op << ")";
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), 8, mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        // 9. VOP1 / VOP2 / VOPC (32-bit Vector ALU)
        else {
            ++out.valu_count;
            if ((w0 >> 25) == 0x3F) {
                uint8_t vdst = static_cast<uint8_t>((w0 >> 17) & 0xFF);
                uint8_t op   = static_cast<uint8_t>((w0 >> 9) & 0xFF);
                mnem = (op == 0x01) ? "v_mov_b32" : "v_vop1";
                ops << "v" << int(vdst) << ", src0=" << int(w0 & 0x1FF);
            } else {
                uint8_t op   = static_cast<uint8_t>((w0 >> 25) & 0x3F);
                uint8_t vdst = static_cast<uint8_t>((w0 >> 17) & 0xFF);
                switch (op) {
                    case 0x03: mnem = "v_add_f32"; break;
                    case 0x04: mnem = "v_sub_f32"; break;
                    case 0x08: mnem = "v_mul_f32"; break;
                    case 0x1B: mnem = "v_and_b32"; break;
                    case 0x1C: mnem = "v_or_b32"; break;
                    case 0x25: mnem = "v_add_nc_u32"; break;
                    case 0x2B: mnem = "v_fmac_f32"; break;
                    default:   mnem = "v_vop2"; break;
                }
                ops << "v" << int(vdst) << ", v" << int((w0 >> 9) & 0xFF);
            }
            if ((w0 & 0x1FF) == 0xFF && pc + 1 < max_dwords) {
                step = 2;
                ops << " [lit=0x" << std::hex << code[pc + 1] << "]";
            }
            if (out.sample_disassembly.size() < max_disasm_lines) {
                out.sample_disassembly.push_back({
                    static_cast<uint32_t>(pc * 4), static_cast<uint8_t>(step * 4), mnem, ops.str()
                });
            }
            ++out.total_instructions;
        }
        pc += step;
    }

    out.code_size_bytes = pc * 4;
    out.code_hash = Fnv1a64(code, out.code_size_bytes);
    return out;
}

std::vector<Rdna2ShaderAnalysis> Rdna2ShaderAnalyzer::ScanShaderPack(
    const std::filesystem::path& xpps_path,
    size_t max_shaders) {
    std::vector<Rdna2ShaderAnalysis> results;
    std::ifstream ifs(xpps_path, std::ios::binary | std::ios::ate);
    if (!ifs) return results;

    auto total_len = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(total_len);
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), total_len)) return results;

    // Scan 4-byte aligned dwords for s_endpgm (0xBF810000 -> bytes 00 00 81 BF)
    // and walk back 64 dwords (256 bytes) to decode the RDNA2 kernel leading up to s_endpgm.
    const auto* dwords = reinterpret_cast<const uint32_t*>(buf.data());
    size_t n_dwords = total_len / 4;

    for (size_t i = 64; i < n_dwords && results.size() < max_shaders; ++i) {
        if (dwords[i] == 0xBF810000U) {
            size_t start_dw = i - 48;
            auto analysis = AnalyzeIsa(dwords + start_dw, 56, 6);
            if (analysis.terminated_by_endpgm && analysis.total_instructions >= 8) {
                results.push_back(std::move(analysis));
                i += 32; // Skip padding after s_endpgm
            }
        }
    }
    return results;
}

std::vector<uint32_t> Rdna2ShaderAnalyzer::EmitMinimalSpirvCompute(
    uint32_t local_size_x,
    uint32_t local_size_y,
    uint32_t local_size_z) {
    // Valid SPIR-V 1.6 compute module with OpCapability Shader, OpMemoryModel Logical GLSL450,
    // OpEntryPoint GLCompute %main "main", OpExecutionMode %main LocalSize X Y Z, and void main() { return; }
    return {
        0x07230203U, // Magic: SPIR-V
        0x00010600U, // Version: 1.6
        0x00000000U, // Generator: YoteiPort RDNA2->SPIR-V Recompiler
        0x00000006U, // Bound: 6 IDs
        0x00000000U, // Schema: 0

        // OpCapability Shader (2 words)
        (2U << 16) | 17U, 1U,
        // OpMemoryModel Logical GLSL450 (3 words)
        (3U << 16) | 14U, 0U, 1U,
        // OpEntryPoint GLCompute(5) %main(1) "main\0" (5 words)
        (5U << 16) | 15U, 5U, 1U, 0x6E69616DU, 0x00000000U,
        // OpExecutionMode %main(1) LocalSize(17) X Y Z (6 words)
        (6U << 16) | 16U, 1U, 17U, local_size_x, local_size_y, local_size_z,
        // %void(2) = OpTypeVoid (2 words)
        (2U << 16) | 19U, 2U,
        // %fn_void(3) = OpTypeFunction %void(2) (3 words)
        (3U << 16) | 33U, 3U, 2U,
        // %main(1) = OpFunction %void(2) None(0) %fn_void(3) (5 words)
        (5U << 16) | 54U, 2U, 1U, 0U, 3U,
        // %entry(4) = OpLabel (2 words)
        (2U << 16) | 248U, 4U,
        // OpReturn (1 word)
        (1U << 16) | 253U,
        // OpFunctionEnd (1 word)
        (1U << 16) | 56U,
    };
}

std::vector<uint32_t> Rdna2ShaderAnalyzer::TranslateRdna2ToSpirv(
    const Rdna2ShaderAnalysis& analysis,
    uint32_t local_size_x,
    uint32_t local_size_y,
    uint32_t local_size_z) {
    uint32_t bound = 10;
    std::vector<uint32_t> body_ops;

    uint32_t prev_uint = 7;
    uint32_t prev_float = 8;

    for (const auto& ins : analysis.sample_disassembly) {
        if (ins.mnemonic == "v_add_f32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 129U);
            body_ops.push_back(6U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_float);
            body_ops.push_back(8U);
            prev_float = res_id;
        } else if (ins.mnemonic == "v_sub_f32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 131U);
            body_ops.push_back(6U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_float);
            body_ops.push_back(8U);
            prev_float = res_id;
        } else if (ins.mnemonic == "v_mul_f32" || ins.mnemonic == "v_fmac_f32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 133U);
            body_ops.push_back(6U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_float);
            body_ops.push_back(8U);
            prev_float = res_id;
        } else if (ins.mnemonic == "v_add_nc_u32" || ins.mnemonic == "s_add_u32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 128U);
            body_ops.push_back(5U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_uint);
            body_ops.push_back(7U);
            prev_uint = res_id;
        } else if (ins.mnemonic == "s_sub_u32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 130U);
            body_ops.push_back(5U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_uint);
            body_ops.push_back(7U);
            prev_uint = res_id;
        } else if (ins.mnemonic == "s_mul_i32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 132U);
            body_ops.push_back(5U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_uint);
            body_ops.push_back(7U);
            prev_uint = res_id;
        } else if (ins.mnemonic == "s_and_b32" || ins.mnemonic == "v_and_b32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 197U);
            body_ops.push_back(5U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_uint);
            body_ops.push_back(7U);
            prev_uint = res_id;
        } else if (ins.mnemonic == "s_or_b32" || ins.mnemonic == "v_or_b32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 198U);
            body_ops.push_back(5U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_uint);
            body_ops.push_back(7U);
            prev_uint = res_id;
        } else if (ins.mnemonic == "s_xor_b32" || ins.mnemonic == "v_xor_b32") {
            uint32_t res_id = bound++;
            body_ops.push_back((5U << 16) | 199U);
            body_ops.push_back(5U);
            body_ops.push_back(res_id);
            body_ops.push_back(prev_uint);
            body_ops.push_back(7U);
            prev_uint = res_id;
        }
    }

    std::vector<uint32_t> spirv = {
        0x07230203U, // Magic: SPIR-V
        0x00010600U, // Version: 1.6
        0x00000000U, // Generator: YoteiPort RDNA2->SPIR-V Recompiler
        bound,       // Bound
        0x00000000U, // Schema: 0

        // OpCapability Shader (2 words)
        (2U << 16) | 17U, 1U,
        // OpMemoryModel Logical GLSL450 (3 words)
        (3U << 16) | 14U, 0U, 1U,
        // OpEntryPoint GLCompute(5) %main(1) "main\0" (5 words)
        (5U << 16) | 15U, 5U, 1U, 0x6E69616DU, 0x00000000U,
        // OpExecutionMode %main(1) LocalSize(17) X Y Z (6 words)
        (6U << 16) | 16U, 1U, 17U, local_size_x, local_size_y, local_size_z,
        // %void(2) = OpTypeVoid (2 words)
        (2U << 16) | 19U, 2U,
        // %fn_void(3) = OpTypeFunction %void(2) (3 words)
        (3U << 16) | 33U, 3U, 2U,
        // %uint(5) = OpTypeInt 32 0 (4 words)
        (4U << 16) | 21U, 5U, 32U, 0U,
        // %float(6) = OpTypeFloat 32 (3 words)
        (3U << 16) | 22U, 6U, 32U,
        // %c_uint1(7) = OpConstant %uint(5) 1 (4 words)
        (4U << 16) | 43U, 5U, 7U, 1U,
        // %c_float1(8) = OpConstant %float(6) 1.0f (4 words)
        (4U << 16) | 43U, 6U, 8U, 0x3F800000U,
        // %main(1) = OpFunction %void(2) None(0) %fn_void(3) (5 words)
        (5U << 16) | 54U, 2U, 1U, 0U, 3U,
        // %entry(4) = OpLabel (2 words)
        (2U << 16) | 248U, 4U,
    };

    spirv.insert(spirv.end(), body_ops.begin(), body_ops.end());
    spirv.push_back((1U << 16) | 253U); // OpReturn
    spirv.push_back((1U << 16) | 56U);  // OpFunctionEnd
    return spirv;
}

std::vector<uint32_t> Rdna2ShaderAnalyzer::EmitMinimalSpirvVertex() {
    // Minimal valid SPIR-V 1.6 Vertex Shader conforming to Vulkan spec
    return {
        0x07230203U, 0x00010600U, 0x00000000U, 5U, 0x00000000U,
        (2U << 16) | 17U, 1U,                                // OpCapability Shader
        (3U << 16) | 14U, 0U, 1U,                            // OpMemoryModel Logical GLSL450
        (5U << 16) | 15U, 0U, 1U, 0x6E69616DU, 0x00000000U,  // OpEntryPoint Vertex %main "main\0"
        (2U << 16) | 19U, 2U,                                // %void = OpTypeVoid
        (3U << 16) | 33U, 3U, 2U,                            // %fn_void = OpTypeFunction %void
        (5U << 16) | 54U, 2U, 1U, 0U, 3U,                    // %main = OpFunction %void None %fn_void
        (2U << 16) | 248U, 4U,                               // %label = OpLabel
        (1U << 16) | 253U,                                   // OpReturn
        (1U << 16) | 56U,                                    // OpFunctionEnd
    };
}

std::vector<uint32_t> Rdna2ShaderAnalyzer::EmitMinimalSpirvFragment() {
    // Minimal valid SPIR-V 1.6 Fragment Shader conforming to Vulkan spec
    return {
        0x07230203U, 0x00010600U, 0x00000000U, 5U, 0x00000000U,
        (2U << 16) | 17U, 1U,                                // OpCapability Shader
        (3U << 16) | 14U, 0U, 1U,                            // OpMemoryModel Logical GLSL450
        (5U << 16) | 15U, 4U, 1U, 0x6E69616DU, 0x00000000U,  // OpEntryPoint Fragment(4) %main "main\0"
        (3U << 16) | 16U, 1U, 7U,                            // OpExecutionMode %main OriginUpperLeft(7)
        (2U << 16) | 19U, 2U,                                // %void = OpTypeVoid
        (3U << 16) | 33U, 3U, 2U,                            // %fn_void = OpTypeFunction %void
        (5U << 16) | 54U, 2U, 1U, 0U, 3U,                    // %main = OpFunction %void None %fn_void
        (2U << 16) | 248U, 4U,                               // %label = OpLabel
        (1U << 16) | 253U,                                   // OpReturn
        (1U << 16) | 56U,                                    // OpFunctionEnd
    };
}

} // namespace yotei::graphics
