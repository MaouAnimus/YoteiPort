#include "graphics/pm4_decoder.h"
#include "graphics/rdna2_shader.h"
#include "graphics/vk_backend.h"
#include "hle/ampr_hle.h"
#include "hle/nid_registry.h"
#include "kernel/filesystem.h"
#include "kernel/memory.h"
#include "kernel/threads.h"
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
    uint64_t current_fs = 0;
    __try { current_fs = _readfsbase_u64(); } __except(1) {}
    std::cout << "  [VEH] Exception 0x" << std::hex << code
              << " at RIP=0x" << ep->ContextRecord->Rip
              << " RAX=0x" << ep->ContextRecord->Rax
              << " RBX=0x" << ep->ContextRecord->Rbx
              << " SegFs=0x" << ep->ContextRecord->SegFs
              << " FSBase=0x" << current_fs << std::dec << std::endl;
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        uint8_t* p = reinterpret_cast<uint8_t*>(ep->ContextRecord->Rip);
        while (p && *p == 0x66) ++p;
        // mov rax, qword ptr fs:[0] -> 64 48 8b 04 25 00 00 00 00 (9 bytes)
        if (p && p[0] == 0x64 && p[1] == 0x48 && p[2] == 0x8B && p[3] == 0x04 && p[4] == 0x25 &&
            *reinterpret_cast<uint32_t*>(p + 5) == 0) {
            uint64_t tcb = yotei::kernel::ThreadManager::Instance().GetCurrentThreadTcb();
            ep->ContextRecord->Rax = tcb;
            ep->ContextRecord->Rip = reinterpret_cast<DWORD64>(p + 9);
            std::cout << "  [VEH] Emulated fs:[0] -> RAX=0x" << std::hex << tcb << std::dec << "\n" << std::flush;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (code == EXCEPTION_BREAKPOINT) {
        // If hit int3 (0xCC), advance RIP by 1 or return
        ep->ContextRecord->Rip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static bool ProbeGuestFunctionSeh(uint64_t fn, uint64_t arg0, uint64_t arg1, uint64_t* out_ret, DWORD* out_exc) {
    __try {
        uint64_t r = yotei::kernel::InvokeGuestSysV(fn, arg0, arg1, 0, 0);
        if (out_ret) *out_ret = r;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (out_exc) *out_exc = GetExceptionCode();
        return false;
    }
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

    // Initialize TLS and Threads
    uint64_t tls_vaddr = 0;
    const uint8_t* tls_data = nullptr;
    size_t tls_filesz = 0, tls_memsz = 0, tls_align = 0;
    if (mapper.GetTlsTemplate(&tls_vaddr, &tls_data, &tls_filesz, &tls_memsz, &tls_align)) {
        yotei::kernel::ThreadManager::Instance().Initialize(
            tls_vaddr, tls_data, tls_filesz, tls_memsz, tls_align);
        std::cout << "[+] Initialized PT_TLS: filesz=0x" << std::hex << tls_filesz
                  << " memsz=0x" << tls_memsz << " align=0x" << tls_align << std::dec << "\n";
    }
    yotei::kernel::ThreadManager::Instance().SetupMainThread();

    // Parse PT_SCE_PROCPARAM
    size_t procparam_sz = 0;
    const uint8_t* procparam_data = mapper.GetProcParamData(&procparam_sz);
    if (procparam_data) {
        yotei::kernel::SceProcParam pp{};
        if (yotei::kernel::ThreadManager::Instance().ParseProcParam(procparam_data, procparam_sz, &pp)) {
            std::cout << "[+] Parsed PT_SCE_PROCPARAM (Magic='ORBI'):\n"
                      << "    SDK Version       : 0x" << std::hex << pp.sdk_version << "\n"
                      << "    Compiler Version  : 0x" << pp.compiler_version << std::dec << "\n"
                      << "    Main Stack Size   : " << pp.main_thread_stack_size << " bytes\n";
        }
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
    yotei::kernel::InvokeGuestSysV(sub_mutex_init, reinterpret_cast<uint64_t>(dummy_mutex_obj), 0);
    std::cout << "[+] sub_cd85f0 returned cleanly!\n";
    const auto& regions = yotei::kernel::GuestMemoryManager::Instance().GetMappedRegions();
    std::cout << "[+] Active Guest Direct/Flexible Memory Regions (" << regions.size() << "):\n";
    for (const auto& reg : regions) {
        std::cout << "    [" << std::setw(12) << std::left << reg.name << "] vaddr=0x"
                  << std::hex << reg.guest_vaddr << " size=0x" << reg.size
                  << " (" << std::dec << (reg.size / (1024 * 1024)) << " MiB) phys=0x"
                  << std::hex << reg.phys_offset << std::dec << "\n";
    }

    // 2. Test sub_24f2c0 (calls scePthreadSelf and returns current thread ID)
    uint64_t sub_pthread_self = mapper.GetBaseAddress() + 0x24f2c0ULL;
    std::cout << "[*] Calling sub_24f2c0 (scePthreadSelf SysV entry) @ 0x"
              << std::hex << sub_pthread_self << std::dec << "...\n" << std::flush;
    uint64_t self_tid = yotei::kernel::InvokeGuestSysV(sub_pthread_self, 0, 0);
    std::cout << "[+] sub_24f2c0 returned TID=" << self_tid << "\n";

    // 3. Test Calling Global Static Constructors @ 0x800000010
    uint64_t global_init = mapper.GetBaseAddress() + 0x10ULL;
    std::cout << "\n[*] Testing Global Static Constructors @ 0x" << std::hex << global_init << std::dec << "...\n" << std::flush;
    uint64_t init_ret = 0;
    DWORD init_exc = 0;
    if (ProbeGuestFunctionSeh(global_init, 0, 0, &init_ret, &init_exc)) {
        std::cout << "[+] Global static constructors executed cleanly!\n";
    } else {
        std::cout << "  [!] Global init exception: 0x" << std::hex << init_exc << std::dec << "\n";
    }

    // 4. Verify AMPR Asynchronous Streaming Command Buffer Execution into Guest Direct Memory
    if (!regions.empty() && vfs.GetAmprEntryCount() > 0) {
        std::cout << "\n--- Testing AMPR Async DMA Streaming & AGC PM4 Decoder ---\n";
        uint64_t guest_crt_base = regions[0].guest_vaddr;
        uint8_t* dst_ptr = reinterpret_cast<uint8_t*>(guest_crt_base + 0x100000ULL);
        uint64_t completion_tag = 0;

        auto& ampr = yotei::hle::AmprHleManager::Instance();
        uint64_t dummy_cb = guest_crt_base + 0x200000ULL;
        uint64_t ret = 0;
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

        // Scan real RDNA2 shaders inside all_shaders.xpps and emit/verify SPIR-V 1.6 on Host Vulkan 1.3 GPU
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

    // 4. Test Calling Game main() @ 0x800f3d320
    uint64_t game_main = mapper.GetMainAddress();
    std::cout << "\n--- Testing Game main() Entry Point (Native x86-64) ---\n";
    std::cout << "[*] Calling Game main() @ 0x" << std::hex << game_main << std::dec << "...\n" << std::flush;
    static const char* dummy_argv[] = { "/app0/eboot.bin", nullptr };
    uint64_t main_ret = 0;
    DWORD exc_code = 0;
    if (ProbeGuestFunctionSeh(game_main, 1, reinterpret_cast<uint64_t>(&dummy_argv[0]), &main_ret, &exc_code)) {
        std::cout << "[+] Game main() returned: " << main_ret << "\n";
    } else {
        std::cout << "  [!] Game main() probe reached unhandled early stub / exception: 0x"
                  << std::hex << exc_code << std::dec << " (Phase 2 stubbing progress)\n";
    }

    // Report any unhandled stubs observed
    yotei::hle::NidRegistry::PrintUnhandledStubSummary();

    RemoveVectoredExceptionHandler(veh);
#endif

    yotei::kernel::ThreadManager::Instance().Shutdown();
    yotei::kernel::GuestMemoryManager::Instance().ReleaseAll();
    registry.FreeTrampolines();
    mapper.Unmap();
    std::cout << "\n[+] Guest native execution probe completed and memory cleanly unmapped.\n";
    return 0;
}
