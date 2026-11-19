#include "loader/elf_mapper.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <unordered_map>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::loader {

namespace {

#pragma pack(push, 1)
struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Dyn {
    uint64_t d_tag;
    uint64_t d_val;
};

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf64_Rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};
#pragma pack(pop)

uint32_t DecodeSceBase64Id(const std::string& s) {
    static const std::string kB64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
    uint32_t val = 0;
    for (char c : s) {
        auto pos = kB64.find(c);
        if (pos != std::string::npos) {
            val = (val << 6) | static_cast<uint32_t>(pos);
        }
    }
    return val;
}

} // namespace

bool ElfMapper::LoadFromDisk(const std::filesystem::path& elf_path) {
    std::ifstream ifs(elf_path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        std::cerr << "[!] Failed to open ELF file: " << elf_path << "\n";
        return false;
    }
    auto file_size = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);
    raw_bytes_.resize(file_size);
    if (!ifs.read(reinterpret_cast<char*>(raw_bytes_.data()), file_size)) {
        return false;
    }

    if (raw_bytes_.size() < sizeof(Elf64_Ehdr) ||
        raw_bytes_[0] != 0x7f || raw_bytes_[1] != 'E' ||
        raw_bytes_[2] != 'L' || raw_bytes_[3] != 'F') {
        std::cerr << "[!] Invalid ELF64 magic in " << elf_path << "\n";
        return false;
    }

    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(raw_bytes_.data());
    e_type_ = ehdr->e_type;
    entry_offset_ = ehdr->e_entry;

    segments_.clear();
    const Elf64_Phdr* dyn_ph = nullptr;
    const Elf64_Phdr* dynlib_ph = nullptr;

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const auto* ph = reinterpret_cast<const Elf64_Phdr*>(
            raw_bytes_.data() + ehdr->e_phoff + i * ehdr->e_phentsize);
        segments_.push_back({
            i,
            ph->p_type,
            ph->p_flags,
            ph->p_offset,
            ph->p_vaddr,
            ph->p_filesz,
            ph->p_memsz,
            ph->p_align,
        });
        if (ph->p_type == 0x2) { // PT_DYNAMIC
            dyn_ph = ph;
        }
        if (ph->p_vaddr == 0x717d610ULL || ph->p_type == 0x61000010) {
            dynlib_ph = ph;
        }
    }

    if (dyn_ph && dynlib_ph) {
        auto vaddr_to_off = [&](uint64_t v) -> size_t {
            return static_cast<size_t>(v - dynlib_ph->p_vaddr + dynlib_ph->p_offset);
        };

        uint64_t strtab_vaddr = 0, strtab_sz = 0;
        uint64_t symtab_vaddr = 0, jmprel_vaddr = 0, jmprel_sz = 0;
        uint64_t rela_vaddr = 0, rela_sz = 0;

        size_t n_dyn = static_cast<size_t>(dyn_ph->p_filesz / sizeof(Elf64_Dyn));
        const auto* dyns = reinterpret_cast<const Elf64_Dyn*>(
            raw_bytes_.data() + dyn_ph->p_offset);

        for (size_t i = 0; i < n_dyn; ++i) {
            if (dyns[i].d_tag == 0) break;
            switch (dyns[i].d_tag) {
                case 2:    jmprel_sz = dyns[i].d_val; break;
                case 5:    strtab_vaddr = dyns[i].d_val; break;
                case 6:    symtab_vaddr = dyns[i].d_val; break;
                case 7:    rela_vaddr = dyns[i].d_val; break;
                case 8:    rela_sz = dyns[i].d_val; break;
                case 10:   strtab_sz = dyns[i].d_val; break;
                case 0x17: jmprel_vaddr = dyns[i].d_val; break;
                default: break;
            }
        }

        size_t strtab_off = vaddr_to_off(strtab_vaddr);
        const char* strtab = reinterpret_cast<const char*>(raw_bytes_.data() + strtab_off);

        std::unordered_map<uint32_t, std::string> libs;
        std::unordered_map<uint32_t, std::string> mods;

        for (size_t i = 0; i < n_dyn; ++i) {
            if (dyns[i].d_tag == 0) break;
            if (dyns[i].d_tag == 0x61000045) {
                uint32_t mid = static_cast<uint32_t>((dyns[i].d_val >> 48) & 0xFFFF);
                uint32_t s_off = static_cast<uint32_t>(dyns[i].d_val & 0xFFFFFFFF);
                if (s_off < strtab_sz) mods[mid] = std::string(strtab + s_off);
            } else if (dyns[i].d_tag == 0x61000049) {
                uint32_t lid = static_cast<uint32_t>((dyns[i].d_val >> 48) & 0xFFFF);
                uint32_t s_off = static_cast<uint32_t>(dyns[i].d_val & 0xFFFFFFFF);
                if (s_off < strtab_sz) libs[lid] = std::string(strtab + s_off);
            }
        }

        size_t symtab_off = vaddr_to_off(symtab_vaddr);
        size_t jmprel_off = vaddr_to_off(jmprel_vaddr);
        size_t n_syms = (jmprel_off - symtab_off) / sizeof(Elf64_Sym);
        const auto* syms = reinterpret_cast<const Elf64_Sym*>(raw_bytes_.data() + symtab_off);

        std::unordered_map<uint32_t, std::vector<std::pair<uint64_t, uint32_t>>> sym_got;
        internal_relocs_.clear();
        auto scan_relas = [&](size_t off, size_t sz) {
            size_t count = sz / sizeof(Elf64_Rela);
            const auto* relas = reinterpret_cast<const Elf64_Rela*>(raw_bytes_.data() + off);
            for (size_t i = 0; i < count; ++i) {
                uint32_t sym_idx = static_cast<uint32_t>(relas[i].r_info >> 32);
                uint32_t r_type = static_cast<uint32_t>(relas[i].r_info & 0xFFFFFFFF);
                if (r_type == 8) { // R_X86_64_RELATIVE
                    internal_relocs_.push_back({relas[i].r_offset, r_type, 0, relas[i].r_addend, 0});
                } else if (r_type == 1 && sym_idx < n_syms) { // R_X86_64_64
                    if (syms[sym_idx].st_value != 0) {
                        internal_relocs_.push_back({
                            relas[i].r_offset, r_type, sym_idx, relas[i].r_addend, syms[sym_idx].st_value
                        });
                    } else if (sym_idx > 0) {
                        sym_got[sym_idx].push_back({relas[i].r_offset, r_type});
                    }
                } else if (sym_idx > 0 && sym_idx < n_syms) {
                    sym_got[sym_idx].push_back({relas[i].r_offset, r_type});
                }
            }
        };

        scan_relas(vaddr_to_off(rela_vaddr), static_cast<size_t>(rela_sz));
        scan_relas(jmprel_off, static_cast<size_t>(jmprel_sz));

        imports_.clear();
        for (uint32_t i = 0; i < n_syms; ++i) {
            if (syms[i].st_name == 0 || syms[i].st_name >= strtab_sz) continue;
            std::string raw(strtab + syms[i].st_name);
            auto p1 = raw.find('#');
            if (p1 == std::string::npos) continue;
            auto p2 = raw.find('#', p1 + 1);
            if (p2 == std::string::npos) continue;

            std::string nid = raw.substr(0, p1);
            std::string lid_s = raw.substr(p1 + 1, p2 - p1 - 1);
            std::string mid_s = raw.substr(p2 + 1);

            uint32_t lid = DecodeSceBase64Id(lid_s);
            uint32_t mid = DecodeSceBase64Id(mid_s);

            auto got_it = sym_got.find(i);
            if (got_it != sym_got.end()) {
                for (const auto& [got_vaddr, r_type] : got_it->second) {
                    imports_.push_back({
                        i,
                        nid,
                        raw,
                        libs.count(lid) ? libs[lid] : lid_s,
                        mods.count(mid) ? mods[mid] : mid_s,
                        got_vaddr,
                        r_type,
                    });
                }
            }
        }
    }

    return true;
}

bool ElfMapper::MapIntoGuestSpace(uint64_t preferred_base) {
    uint64_t max_vaddr = 0;
    for (const auto& seg : segments_) {
        if (seg.type == 0x1 && seg.flags != 0) { // Loadable RWX segments
            max_vaddr = (std::max)(max_vaddr, seg.vaddr + seg.memsz);
        }
    }
    if (max_vaddr == 0) return false;

    // Align up to 64 KiB boundary
    total_mapped_span_ = (max_vaddr + 0xFFFFULL) & ~0xFFFFULL;

#ifdef _WIN32
    void* mem = VirtualAlloc(
        reinterpret_cast<void*>(preferred_base),
        static_cast<SIZE_T>(total_mapped_span_),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    if (!mem) {
        mem = VirtualAlloc(
            nullptr,
            static_cast<SIZE_T>(total_mapped_span_),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
    }
    if (!mem) {
        std::cerr << "[!] VirtualAlloc failed for guest span " << std::hex << total_mapped_span_ << "\n";
        return false;
    }
    base_address_ = reinterpret_cast<uint64_t>(mem);

    for (const auto& seg : segments_) {
        if (seg.type == 0x1 && seg.flags != 0 && seg.filesz > 0) {
            std::memcpy(
                reinterpret_cast<uint8_t*>(base_address_ + seg.vaddr),
                raw_bytes_.data() + seg.file_offset,
                static_cast<size_t>(seg.filesz));
        }
    }
    return true;
#else
    return false;
#endif
}

size_t ElfMapper::ApplyInternalRelocations() {
    if (base_address_ == 0) return 0;
    size_t applied = 0;
    for (const auto& rel : internal_relocs_) {
        auto* target = reinterpret_cast<uint64_t*>(base_address_ + rel.r_offset);
        if (rel.r_type == 8) { // R_X86_64_RELATIVE: B + A
            *target = static_cast<uint64_t>(static_cast<int64_t>(base_address_) + rel.r_addend);
            ++applied;
        } else if (rel.r_type == 1) { // R_X86_64_64: S + A
            *target = static_cast<uint64_t>(static_cast<int64_t>(base_address_ + rel.sym_value) + rel.r_addend);
            ++applied;
        }
    }
    return applied;
}

bool ElfMapper::EnableExecutionPermissions() {
#ifdef _WIN32
    if (base_address_ == 0) return false;
    DWORD old_prot = 0;
    return VirtualProtect(
        reinterpret_cast<void*>(base_address_),
        static_cast<SIZE_T>(total_mapped_span_),
        PAGE_EXECUTE_READWRITE,
        &old_prot) != 0;
#else
    return false;
#endif
}

void ElfMapper::Unmap() {
#ifdef _WIN32
    if (base_address_ != 0) {
        VirtualFree(reinterpret_cast<void*>(base_address_), 0, MEM_RELEASE);
        base_address_ = 0;
    }
#endif
}

} // namespace yotei::loader
