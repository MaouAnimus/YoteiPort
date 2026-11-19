#include "graphics/pm4_decoder.h"
#include "graphics/rdna2_shader.h"
#include "graphics/vk_backend.h"
#include "hle/ampr_hle.h"
#include "hle/nid_registry.h"
#include "kernel/filesystem.h"
#include "kernel/memory.h"
#include "loader/elf_mapper.h"
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {

#ifdef _WIN32
LONG WINAPI GuestVehHandler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    std::cout << "  [VEH] Exception 0x" << std::hex << code
              << " at RIP=0x" << ep->ContextRecord->Rip
              << " RAX=0x" << ep->ContextRecord->Rax
              << " RBX=0x" << ep->ContextRecord->Rbx << std::dec << std::endl;
    if (code == EXCEPTION_BREAKPOINT) {
        // If hit int3 (0xCC), advance RIP by 1 or return
        ep->ContextRecord->Rip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

uint64_t InvokeGuestSysV(uint64_t fn_addr, uint64_t rdi_arg, uint64_t rsi_arg) {
    uint8_t caller_code[] = {
        0x55,                                     // push rbp
        0x48, 0x89, 0xE5,                         // mov rbp, rsp
        0x41, 0x57,                               // push r15
        0x41, 0x56,                               // push r14
        0x41, 0x55,                               // push r13
        0x41, 0x54,                               // push r12
        0x57,                                     // push rdi
        0x56,                                     // push rsi
        0x53,                                     // push rbx
        0x48, 0x83, 0xEC, 0x08,                   // sub rsp, 8 (16-byte align)
        0x48, 0x89, 0xD7,                         // mov rdi, rdx (rdi_arg)
        0x4C, 0x89, 0xC6,                         // mov rsi, r8  (rsi_arg)
        0xFF, 0xD1,                               // call rcx     (fn_addr)
        0x48, 0x8D, 0x65, 0xC8,                   // lea rsp, [rbp - 56]
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
    void* exec_mem = VirtualAlloc(nullptr, 64, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    std::memcpy(exec_mem, caller_code, sizeof(caller_code));
    using GateFn = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t);
    auto gate = reinterpret_cast<GateFn>(exec_mem);
    uint64_t result = gate(fn_addr, rdi_arg, rsi_arg);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return result;
}
#endif

} // namespace

int main(int argc, char** argv) {
    std::filesystem::path root = "c:\\Users\\Alvaro\\Downloads\\Projects\\YoteiPort";
    std::filesystem::path elf_path = root / "extracted_elf" / "eboot.elf";
    std::filesystem::path nid_json = root / "docs" / "nid_resolution_table.json";

    if (argc > 1) elf_path = argv[1];
    if (argc > 2) nid_json = argv[2];

    std::cout << "=================================================================\n";
    std::cout << " Ghost of Yotei (PPSA26344 v02.002.000) Native HLE Runtime Loader\n";
    std::cout << "=================================================================\n" << std::flush;

    yotei::loader::ElfMapper mapper;
    if (!mapper.LoadFromDisk(elf_path)) {
        return 1;
    }

    std::cout << "[+] Loaded ELF64 image: " << elf_path.filename().string() << "\n";
    std::cout << "[+] Program Headers   : " << mapper.GetSegments().size() << "\n";
    std::cout << "[+] Imported Relocs   : " << mapper.GetImports().size() << "\n";

    yotei::hle::NidRegistry registry;
    if (registry.LoadResolutionTable(nid_json)) {
        std::cout << "[+] Loaded NID Table  : " << registry.GetTotalRegistered() << " entries\n";
    }

    if (!mapper.MapIntoGuestSpace()) {
        return 1;
    }

    std::cout << "[+] Mapped into Guest Virtual Address Space:\n";
    std::cout << "    Base Address      : 0x" << std::hex << mapper.GetBaseAddress() << "\n";
    std::cout << "    Entry Point (crt1): 0x" << std::hex << mapper.GetEntryPoint() << "\n";
    std::cout << "    Game main()       : 0x" << std::hex << mapper.GetMainAddress() << std::dec << "\n";

    size_t relocs = mapper.ApplyInternalRelocations();
    std::cout << "[+] Applied Internal Relocations (R_X86_64_RELATIVE / 64): " << relocs << "\n";

    size_t bound = registry.BindImportsToGuestGot(mapper.GetBaseAddress(), mapper.GetImports());
    std::cout << "[+] Patched Guest GOT with SysV->MSx64 HLE Trampolines   : "
              << bound << " / " << mapper.GetImports().size() << "\n";

    if (!mapper.EnableExecutionPermissions()) {
        std::cerr << "[!] Failed to set PAGE_EXECUTE_READWRITE on guest span\n";
        return 1;
    }

    // Mount virtual filesystems (/app0, /cache_ps5) and load AMPRIDX3 index
    auto& vfs = yotei::kernel::VirtualFileSystem::Instance();
    std::filesystem::path app0_dir = root / "PPSA26344" / "PPSA26344-app";
    if (std::filesystem::exists(app0_dir)) {
        vfs.Mount("/app0", app0_dir);
        vfs.Mount("/cache_ps5", app0_dir / "cache_ps5");
        vfs.Mount("/app0/cache_ps5", app0_dir / "cache_ps5");
        std::cout << "[+] Mounted Guest VFS: /app0 -> " << app0_dir.string() << "\n";
        if (vfs.LoadAmprIndex(app0_dir / "ampr_emu.index")) {
            std::cout << "[+] Loaded AMPRIDX3  : " << vfs.GetAmprEntryCount()
                      << " streaming files indexed\n";
            uint32_t shader_pack_id = 0;
            uint64_t shader_pack_sz = 0;
            if (vfs.AprResolvePath("/app0/cache_ps5/all_shaders.xpps", &shader_pack_id, &shader_pack_sz) == 0) {
                std::cout << "    Verified APR Resolve '/app0/cache_ps5/all_shaders.xpps' -> ID="
                          << shader_pack_id << " (" << shader_pack_sz << " bytes)\n";
            }
        }
    }
    std::cout << std::flush;

#ifdef _WIN32
    PVOID veh = AddVectoredExceptionHandler(1, GuestVehHandler);
    std::cout << "\n--- Executing Guest Early Boot Functions (Native x86-64) ---\n";

    // 1. Test sub_cd85f0 (Engine Memory Pool & Virtual Path Table Init: /app0, /cache_ps5, /host/%ART%)
    void* dummy_mutex_obj = VirtualAlloc(nullptr, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    uint64_t sub_mutex_init = mapper.GetBaseAddress() + 0xcd85f0ULL;
    std::cout << "[*] Calling sub_cd85f0 (Engine Memory & Virtual Path Table Init) @ 0x"
              << std::hex << sub_mutex_init << std::dec << "...\n" << std::flush;
    InvokeGuestSysV(sub_mutex_init, reinterpret_cast<uint64_t>(dummy_mutex_obj), 0);
    std::cout << "[+] sub_cd85f0 returned cleanly!\n";
    const auto& regions = yotei::kernel::GuestMemoryManager::Instance().GetMappedRegions();
    std::cout << "[+] Active Guest Direct/Flexible Memory Regions (" << regions.size() << "):\n";
    for (const auto& reg : regions) {
        std::cout << "    [" << std::setw(12) << std::left << reg.name << "] vaddr=0x"
                  << std::hex << reg.guest_vaddr << " size=0x" << reg.size
                  << " (" << std::dec << (reg.size / (1024 * 1024)) << " MiB) phys=0x"
                  << std::hex << reg.phys_offset << std::dec << "\n";
    }

    // 2. Verify AMPR Asynchronous Streaming Command Buffer Execution into Guest Direct Memory
    if (!regions.empty() && vfs.GetAmprEntryCount() > 0) {
        std::cout << "\n--- Testing AMPR Async DMA Streaming & AGC PM4 Decoder ---\n";
        uint64_t guest_crt_base = regions[0].guest_vaddr;
        uint8_t* dst_ptr = reinterpret_cast<uint8_t*>(guest_crt_base + 0x100000ULL);
        uint64_t completion_tag = 0;

        auto& ampr = yotei::hle::AmprHleManager::Instance();
        uint64_t dummy_cb = guest_crt_base + 0x200000ULL;
        uint64_t ret = 0;
        // Construct APR command buffer, enqueue ReadFile for ID=2 (all_shaders.xpps, first 64 bytes), write completion tag, and submit!
        ampr.DispatchNid("Qs1xtplKo0U", "Ampr::AprCommandBufferConstructor", dummy_cb, 0, 0, 0, 0, 0, &ret);
        ampr.DispatchNid("mZSbNJVJpV8", "Ampr::AprCommandBufferReadFile", dummy_cb, reinterpret_cast<uint64_t>(dst_ptr), 2, 64, 0, 0, &ret);
        ampr.DispatchNid("jK+yuYCI7MA", "Ampr::CommandBufferWriteAddressOnCompletion", dummy_cb, reinterpret_cast<uint64_t>(&completion_tag), 0xCAFEBABEULL, 0, 0, 0, &ret);
        ampr.DispatchNid("eE4Szl8sil8", "Apr::SubmitCommandBuffer", dummy_cb, 0, 0, 0, 0, 0, &ret);

        std::string magic(reinterpret_cast<const char*>(dst_ptr), 4);
        std::cout << "[+] AMPR Streamed File ID=2 ('all_shaders.xpps') into Guest Memory @ 0x"
                  << std::hex << reinterpret_cast<uint64_t>(dst_ptr)
                  << " | Magic='" << magic << "' | CompletionTag=0x" << completion_tag << std::dec
                  << " | Bytes=" << ampr.GetTotalBytesStreamed() << "\n";

        // Verify AGC PM4 Command Stream Decoder on a synthetic Ghost of Yotei pass packet stream
        uint32_t sample_pm4[] = {
            (3U << 30) | (3U << 16) | (0x10U << 8), 0x68757350U, 0x43205343U, 0x68746F6CU, 0x00000000U, // IT_NOP ("CS Cloth")
            (3U << 30) | (2U << 16) | (0x76U << 8), 0x00000004U, 0x801A0000U, 0x00000008U,              // IT_SET_SH_REG
            (3U << 30) | (2U << 16) | (0x15U << 8), 64U, 1U, 1U,                                        // IT_DISPATCH_DIRECT (64,1,1)
        };
        auto pkts = yotei::graphics::AgcPm4Backend::Instance().DecodeCommandStream(sample_pm4, 13);
        std::cout << "[+] AGC PM4 Decoder parsed " << pkts.size() << " RDNA2 packets:\n";
        for (const auto& p : pkts) {
            std::cout << "    [" << std::setw(18) << std::left << p.name << "] ("
                      << p.dword_count << " dwords) " << p.details << "\n";
        }

        // 3. Scan real RDNA2 shaders inside all_shaders.xpps and emit/verify SPIR-V 1.6 on Host Vulkan 1.3 GPU
        std::cout << "\n--- Testing RDNA2 ISA Disassembler & Host Vulkan 1.3 SPIR-V Pipeline ---\n";
        auto shaders = yotei::graphics::Rdna2ShaderAnalyzer::ScanShaderPack(
            app0_dir / "cache_ps5" / "all_shaders.xpps", 4);
        std::cout << "[+] Decoded " << shaders.size()
                  << " RDNA2 Shader Kernels from 'all_shaders.xpps':\n";
        for (size_t s = 0; s < shaders.size(); ++s) {
            const auto& sh = shaders[s];
            std::cout << "    Shader[" << s << "] hash=0x" << std::hex << sh.code_hash << std::dec
                      << " | insns=" << sh.total_instructions
                      << " (SALU=" << sh.salu_count << " VALU=" << sh.valu_count
                      << " SMEM=" << sh.smem_count << " VMEM/MIMG=" << sh.vmem_mimg_count << ")\n";
            for (const auto& ins : sh.sample_disassembly) {
                std::cout << "      +" << std::setw(3) << ins.offset_bytes << ": "
                          << std::setw(22) << std::left << ins.mnemonic << " " << ins.operands << "\n";
            }
        }
        std::cout << std::flush;

        auto& vk = yotei::graphics::VulkanHostBackend::Instance();
        if (vk.Initialize()) {
            const auto& gpu = vk.GetGpuInfo();
            auto spirv = yotei::graphics::Rdna2ShaderAnalyzer::EmitMinimalSpirvCompute(64, 1, 1);
            bool sm_ok = vk.VerifySpirvShaderModule(spirv);
            std::cout << "[+] Initialized Host Vulkan " << gpu.api_version_major << "."
                      << gpu.api_version_minor << "." << gpu.api_version_patch << " Device:\n"
                      << "    GPU Name      : " << gpu.device_name << "\n"
                      << "    Dedicated VRAM: " << (gpu.vram_bytes / (1024 * 1024)) << " MiB\n"
                      << "    SPIR-V Module : " << (sm_ok ? "VkShaderModule compiled & verified on GPU!" : "failed")
                      << " (" << spirv.size() * 4 << " bytes)\n";
            vk.Shutdown();
        }
    }
    std::cout << std::flush;

    RemoveVectoredExceptionHandler(veh);
#endif

    yotei::kernel::GuestMemoryManager::Instance().ReleaseAll();
    registry.FreeTrampolines();
    mapper.Unmap();
    std::cout << "\n[+] Guest native execution probe completed and memory cleanly unmapped.\n";
    return 0;
}
