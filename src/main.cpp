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
    // Notice our caller_code uses standard push/sub rsp without changing RBP until after!
    //Even better: allocate a simple function that doesn't modify RSP/RBP across the call so Windows x64 SEH can unwind!
    uint8_t caller_code[] = {
        0x57,                                     // push rdi
        0x56,                                     // push rsi
        0x53,                                     // push rbx
        0x48, 0x83, 0xEC, 0x20,                   // sub rsp, 32 (16-byte aligned because 3 pushes + ret addr = 32 bytes)
        0x48, 0x89, 0xD7,                         // mov rdi, rdx (rdi_arg)
        0x4C, 0x89, 0xC6,                         // mov rsi, r8  (rsi_arg)
        0xFF, 0xD1,                               // call rcx     (fn_addr)
        0x48, 0x83, 0xC4, 0x20,                   // add rsp, 32
        0x5B,                                     // pop rbx
        0x5E,                                     // pop rsi
        0x5F,                                     // pop rdi
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
    static uint8_t dummy_mutex_obj[256] = {0};
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
    std::cout << std::flush;

    RemoveVectoredExceptionHandler(veh);
#endif

    yotei::kernel::GuestMemoryManager::Instance().ReleaseAll();
    registry.FreeTrampolines();
    mapper.Unmap();
    std::cout << "\n[+] Guest native execution probe completed and memory cleanly unmapped.\n";
    return 0;
}
