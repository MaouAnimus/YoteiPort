#pragma once
#include "loader/elf_mapper.h"
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>

namespace yotei::hle {

struct NidEntry {
    std::string nid;
    std::string resolved_name;
    std::string library;
    std::string resolution_source;
    uint64_t host_stub_address = 0;
};

class NidRegistry {
public:
    bool LoadResolutionTable(const std::filesystem::path& json_path);
    size_t BindImportsToGuestGot(
        uint64_t guest_base,
        const std::vector<loader::ImportedSymbol>& imports);

    const NidEntry* Lookup(const std::string& nid) const;
    size_t GetTotalRegistered() const { return table_.size(); }
    void FreeTrampolines();

private:
    std::unordered_map<std::string, NidEntry> table_;
    void* trampoline_slab_ = nullptr;
};

} // namespace yotei::hle
