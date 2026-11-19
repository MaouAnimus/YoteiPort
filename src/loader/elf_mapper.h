#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace yotei::loader {

struct ProgramSegment {
    uint32_t index;
    uint32_t type;
    uint32_t flags;
    uint64_t file_offset;
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};

struct ImportedSymbol {
    uint32_t sym_index;
    std::string nid;
    std::string raw_name;
    std::string library;
    std::string module_name;
    uint64_t got_vaddr;
    uint32_t reloc_type;
};

class ElfMapper {
public:
    bool LoadFromDisk(const std::filesystem::path& elf_path);
    bool MapIntoGuestSpace(uint64_t preferred_base = 0x0000000800000000ULL);
    size_t ApplyInternalRelocations();
    bool EnableExecutionPermissions();
    void Unmap();

    uint64_t GetBaseAddress() const { return base_address_; }
    uint64_t GetEntryPoint() const { return base_address_ + entry_offset_; }
    uint64_t GetMainAddress() const { return base_address_ + 0xf3d320ULL; }
    const std::vector<ProgramSegment>& GetSegments() const { return segments_; }
    const std::vector<ImportedSymbol>& GetImports() const { return imports_; }

private:
    struct InternalReloc {
        uint64_t r_offset;
        uint32_t r_type;
        uint32_t sym_idx;
        int64_t  r_addend;
        uint64_t sym_value;
    };

    std::vector<uint8_t> raw_bytes_;
    uint16_t e_type_ = 0;
    uint64_t entry_offset_ = 0;
    uint64_t base_address_ = 0;
    uint64_t total_mapped_span_ = 0;
    std::vector<ProgramSegment> segments_;
    std::vector<ImportedSymbol> imports_;
    std::vector<InternalReloc> internal_relocs_;
};

} // namespace yotei::loader
