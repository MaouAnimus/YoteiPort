#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace yotei::graphics {

struct Rdna2Instruction {
    uint32_t offset_bytes;
    uint8_t  size_bytes; // 4 or 8
    std::string mnemonic;
    std::string operands;
};

struct Rdna2ShaderAnalysis {
    uint64_t code_hash = 0;
    size_t   code_size_bytes = 0;
    uint32_t total_instructions = 0;
    uint32_t salu_count = 0;
    uint32_t valu_count = 0;
    uint32_t smem_count = 0;
    uint32_t vmem_mimg_count = 0;
    uint32_t bvh_intersect_count = 0;
    uint32_t ds_lds_count = 0;
    uint32_t exp_count = 0;
    uint32_t branch_count = 0;
    uint32_t srt_load_count = 0;
    uint32_t texture_sample_count = 0;
    bool     terminated_by_endpgm = false;
    std::vector<Rdna2Instruction> sample_disassembly;
};

class Rdna2ShaderAnalyzer {
public:
    // Analyze a single RDNA2 ISA instruction stream (up to s_endpgm or max_dwords)
    static Rdna2ShaderAnalysis AnalyzeIsa(
        const uint32_t* code,
        size_t max_dwords,
        size_t max_disasm_lines = 12);

    // Scan a KCAP (.xpps) shader pack in memory or on disk for RDNA2 shaders ending in s_endpgm
    static std::vector<Rdna2ShaderAnalysis> ScanShaderPack(
        const std::filesystem::path& xpps_path,
        size_t max_shaders = 10);

    // Emit a minimal valid SPIR-V v1.6 compute shader binary wrapper for a decoded RDNA2 dispatch
    static std::vector<uint32_t> EmitMinimalSpirvCompute(
        uint32_t local_size_x = 64,
        uint32_t local_size_y = 1,
        uint32_t local_size_z = 1);

    // Emit a minimal valid SPIR-V v1.6 vertex shader binary
    static std::vector<uint32_t> EmitMinimalSpirvVertex();

    // Emit a minimal valid SPIR-V v1.6 fragment/pixel shader binary
    static std::vector<uint32_t> EmitMinimalSpirvFragment();

    // Emit a 3D Lit Mesh SPIR-V v1.6 Vertex Shader (Location 0: vec4 ClipPos, Location 1: vec4 Color -> gl_Position + Location 0 outColor)
    static std::vector<uint32_t> EmitLitMeshSpirvVertex();

    // Emit a 3D Lit Mesh SPIR-V v1.6 Fragment Shader (Location 0: vec4 inColor -> Location 0 outFragColor)
    static std::vector<uint32_t> EmitLitMeshSpirvFragment();

    // Translate a decoded RDNA2 shader into an executable Vulkan SPIR-V compute module
    static std::vector<uint32_t> TranslateRdna2ToSpirv(
        const Rdna2ShaderAnalysis& analysis,
        uint32_t local_size_x = 64,
        uint32_t local_size_y = 1,
        uint32_t local_size_z = 1);

    // Translate a decoded RDNA2 shader into an executable Vulkan SPIR-V Vertex module
    static std::vector<uint32_t> TranslateRdna2ToVertexSpirv(
        const Rdna2ShaderAnalysis& analysis);

    // Translate a decoded RDNA2 shader into an executable Vulkan SPIR-V Fragment module
    static std::vector<uint32_t> TranslateRdna2ToFragmentSpirv(
        const Rdna2ShaderAnalysis& analysis);
};

} // namespace yotei::graphics
