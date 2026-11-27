#include "kernel/filesystem.h"
#include <algorithm>
#include <cstring>
#include <iostream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::kernel {

namespace {

#pragma pack(push, 1)
struct AmprHeader {
    char     magic[8]; // "AMPRIDX3"
    uint32_t version;
    uint32_t hdr_size;
    uint64_t num_files;
    uint64_t str_table_size;
    uint64_t meta_offset;
    uint8_t  pad[24];
};

struct AmprRawRecord {
    uint64_t path_hash;
    uint32_t str_offset;
    uint32_t str_length;
    uint64_t file_size;
};
#pragma pack(pop)

std::string NormalizeSlashes(std::string s) {
    std::replace(s.begin(), s.end(), '\\', '/');
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

} // namespace

VirtualFileSystem& VirtualFileSystem::Instance() {
    static VirtualFileSystem instance;
    return instance;
}

void VirtualFileSystem::Mount(const std::string& guest_prefix, const std::filesystem::path& host_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string norm = NormalizeSlashes(guest_prefix);
    for (auto& m : mounts_) {
        if (m.first == norm) {
            m.second = host_dir;
            return;
        }
    }
    mounts_.emplace_back(norm, host_dir);
    // Keep longest prefixes first so /app0/cache_ps5 matches before /app0
    std::sort(mounts_.begin(), mounts_.end(), [](const auto& a, const auto& b) {
        return a.first.size() > b.first.size();
    });
}

std::filesystem::path VirtualFileSystem::ResolveGuestPath(const std::string& guest_path) const {
    std::string norm = NormalizeSlashes(guest_path);
    for (const auto& [prefix, host_dir] : mounts_) {
        if (norm.rfind(prefix, 0) == 0) {
            std::string rel = norm.substr(prefix.size());
            while (!rel.empty() && rel.front() == '/') rel.erase(rel.begin());
            return rel.empty() ? host_dir : (host_dir / std::filesystem::path(rel));
        }
    }
    return {};
}

bool VirtualFileSystem::LoadAmprIndex(const std::filesystem::path& index_path) {
    std::ifstream ifs(index_path, std::ios::binary | std::ios::ate);
    if (!ifs) return false;
    auto total_size = static_cast<size_t>(ifs.tellg());
    if (total_size < sizeof(AmprHeader)) return false;

    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(total_size);
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), total_size)) return false;

    const auto* hdr = reinterpret_cast<const AmprHeader*>(buf.data());
    if (std::memcmp(hdr->magic, "AMPRIDX3", 8) != 0) return false;

    size_t records_offset = 0x40;
    size_t str_base = records_offset + static_cast<size_t>(hdr->num_files) * sizeof(AmprRawRecord);
    if (str_base > total_size) return false;

    const auto* recs = reinterpret_cast<const AmprRawRecord*>(buf.data() + records_offset);
    const char* str_tbl = reinterpret_cast<const char*>(buf.data() + str_base);

    std::lock_guard<std::mutex> lock(mutex_);
    ampr_by_path_.clear();
    ampr_by_id_.clear();
    ampr_by_path_.reserve(static_cast<size_t>(hdr->num_files));
    ampr_by_id_.reserve(static_cast<size_t>(hdr->num_files));

    for (uint64_t i = 0; i < hdr->num_files; ++i) {
        if (str_base + recs[i].str_offset + recs[i].str_length > total_size) continue;
        const char* raw_s = str_tbl + recs[i].str_offset;
        size_t len = recs[i].str_length;

        // Format is "<rel_path>\0<mount_point>"
        std::string rel_path(raw_s);
        std::string mount_pt = "/app0/cache_ps5";
        if (rel_path.size() + 1 < len) {
            mount_pt = std::string(raw_s + rel_path.size() + 1, len - rel_path.size() - 1);
            // Strip trailing NULs if any
            if (auto nul = mount_pt.find('\0'); nul != std::string::npos) {
                mount_pt.resize(nul);
            }
        }

        std::string full_vpath = NormalizeSlashes(mount_pt + "/" + rel_path);
        uint32_t file_id = static_cast<uint32_t>(i + 1);
        AmprIndexEntry entry{
            recs[i].path_hash,
            recs[i].file_size,
            full_vpath,
            mount_pt,
            file_id,
        };
        ampr_by_path_[full_vpath] = entry;
        ampr_by_path_[rel_path] = entry;
        ampr_by_id_[file_id] = std::move(entry);
    }
    return true;
}

int32_t VirtualFileSystem::Open(const char* guest_path, int32_t /*flags*/, int32_t /*mode*/) {
    if (!guest_path || reinterpret_cast<uintptr_t>(guest_path) < 0x1000) return -14; // EFAULT
    auto host_path = ResolveGuestPath(guest_path);
    std::error_code ec;
    if (host_path.empty() || !std::filesystem::exists(host_path, ec)) {
        return -2; // SCE_KERNEL_ERROR_ENOENT
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int32_t fd = next_fd_++;
    if (std::filesystem::is_directory(host_path, ec)) {
        open_fds_[fd] = {host_path, nullptr, 0, true};
        return fd;
    }

    auto stream = std::make_shared<std::ifstream>(host_path, std::ios::binary);
    if (!stream->is_open()) return -13; // EACCES
    uint64_t fsize = static_cast<uint64_t>(std::filesystem::file_size(host_path, ec));
    open_fds_[fd] = {host_path, stream, fsize, false};
    return fd;
}

int32_t VirtualFileSystem::Close(int32_t fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) return -9; // EBADF
    open_fds_.erase(it);
    return 0;
}

int64_t VirtualFileSystem::Read(int32_t fd, void* buf, uint64_t count) {
    if (!buf || reinterpret_cast<uintptr_t>(buf) < 0x1000) return -14;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end() || !it->second.stream) return -9;
    it->second.stream->clear();
    it->second.stream->read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(count));
    return static_cast<int64_t>(it->second.stream->gcount());
}

int64_t VirtualFileSystem::Write(int32_t /*fd*/, const void* buf, uint64_t count) {
    if (!buf || reinterpret_cast<uintptr_t>(buf) < 0x1000) return -14;
    return static_cast<int64_t>(count);
}

int64_t VirtualFileSystem::Lseek(int32_t fd, int64_t offset, int32_t whence) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end() || !it->second.stream) return -9;
    it->second.stream->clear();
    std::ios_base::seekdir dir = std::ios::beg;
    if (whence == 1) dir = std::ios::cur;
    else if (whence == 2) dir = std::ios::end;
    it->second.stream->seekg(static_cast<std::streamoff>(offset), dir);
    return static_cast<int64_t>(it->second.stream->tellg());
}

int64_t VirtualFileSystem::Pread(int32_t fd, void* buf, uint64_t count, int64_t offset) {
    if (!buf || reinterpret_cast<uintptr_t>(buf) < 0x1000 || offset < 0) return -22;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end() || !it->second.stream) return -9;
    it->second.stream->clear();
    it->second.stream->seekg(offset, std::ios::beg);
    it->second.stream->read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(count));
    return static_cast<int64_t>(it->second.stream->gcount());
}

int32_t VirtualFileSystem::Stat(const char* guest_path, SceKernelStat* sb) {
    if (!guest_path || reinterpret_cast<uintptr_t>(guest_path) < 0x1000 || !sb || reinterpret_cast<uintptr_t>(sb) < 0x1000) return -14;
    auto host_path = ResolveGuestPath(guest_path);
    std::error_code ec;
    if (host_path.empty() || !std::filesystem::exists(host_path, ec)) return -2;

    std::memset(sb, 0, sizeof(SceKernelStat));
    bool is_dir = std::filesystem::is_directory(host_path, ec);
    sb->st_mode = is_dir ? 0040777 : 0100666;
    sb->st_size = is_dir ? 0 : static_cast<int64_t>(std::filesystem::file_size(host_path, ec));
    sb->st_blksize = 4096;
    return 0;
}

int32_t VirtualFileSystem::Fstat(int32_t fd, SceKernelStat* sb) {
    if (!sb || reinterpret_cast<uintptr_t>(sb) < 0x1000) return -14;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) return -9;
    std::memset(sb, 0, sizeof(SceKernelStat));
    sb->st_mode = it->second.is_directory ? 0040777 : 0100666;
    sb->st_size = static_cast<int64_t>(it->second.file_size);
    sb->st_blksize = 4096;
    return 0;
}

int32_t VirtualFileSystem::AprResolvePath(
    const std::string& virtual_path,
    uint32_t* out_id,
    uint64_t* out_size) const {
    std::string norm = NormalizeSlashes(virtual_path);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ampr_by_path_.find(norm);
        if (it != ampr_by_path_.end()) {
            if (out_id) *out_id = it->second.apr_file_id;
            if (out_size) *out_size = it->second.file_size;
            return 0;
        }
    }
    // Fallback to direct host filesystem check and dynamically index it
    auto host_path = ResolveGuestPath(norm);
    std::error_code ec;
    if (!host_path.empty() && std::filesystem::exists(host_path, ec)) {
        bool is_dir = std::filesystem::is_directory(host_path, ec);
        uint64_t fsz = is_dir ? 0 : static_cast<uint64_t>(std::filesystem::file_size(host_path, ec));
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t dyn_id = static_cast<uint32_t>(ampr_by_id_.size() + 1);
        AmprIndexEntry entry{0, fsz, norm, "/app0", dyn_id};
        ampr_by_path_[norm] = entry;
        ampr_by_id_[dyn_id] = std::move(entry);
        if (out_id) *out_id = dyn_id;
        if (out_size) *out_size = fsz;
        return 0;
    }
    return static_cast<int32_t>(0x80020002); // SCE_KERNEL_ERROR_ENOENT
}

int32_t VirtualFileSystem::AprStatFileById(uint32_t file_id, SceKernelStat* sb) const {
    if (!sb || reinterpret_cast<uintptr_t>(sb) < 0x1000) return static_cast<int32_t>(0x8002000e);
    std::string vpath;
    uint64_t fsz = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ampr_by_id_.find(file_id);
        if (it == ampr_by_id_.end()) return static_cast<int32_t>(0x80020002);
        vpath = it->second.virtual_path;
        fsz = it->second.file_size;
    }
    auto host_path = ResolveGuestPath(vpath);
    std::error_code ec;
    bool is_dir = (!host_path.empty() && std::filesystem::is_directory(host_path, ec));
    std::memset(sb, 0, sizeof(SceKernelStat));
    sb->st_mode = is_dir ? 0040777 : 0100666;
    sb->st_size = is_dir ? 0 : static_cast<int64_t>(fsz);
    sb->st_blksize = 4096;
    return 0;
}

int32_t VirtualFileSystem::AprGetFileSize(uint32_t file_id, uint64_t* out_size) const {
    if (!out_size || reinterpret_cast<uintptr_t>(out_size) < 0x1000) return static_cast<int32_t>(0x8002000e);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = ampr_by_id_.find(file_id);
    if (it == ampr_by_id_.end()) return static_cast<int32_t>(0x80020002);
    *out_size = it->second.file_size;
    return 0;
}

int64_t VirtualFileSystem::AprReadFileById(
    uint32_t file_id,
    void* dst_buf,
    uint64_t length,
    uint64_t offset) const {
    std::string vpath;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ampr_by_id_.find(file_id);
        if (it == ampr_by_id_.end()) return -2;
        vpath = it->second.virtual_path;
    }
    auto host_path = ResolveGuestPath(vpath);
    std::ifstream ifs(host_path, std::ios::binary);
    if (!ifs) return -2;
#ifdef _WIN32
    // Ensure all pages in [dst_buf, dst_buf + length) are committed in host virtual address space
    // (e.g. if the guest reserved a sparse virtual range at 0x8000000000 or mapped a partial direct memory block)
    uint64_t start_va = reinterpret_cast<uint64_t>(dst_buf) & ~0xFFFFULL;
    uint64_t end_va   = (reinterpret_cast<uint64_t>(dst_buf) + length + 0xFFFFULL) & ~0xFFFFULL;
    for (uint64_t page_va = start_va; page_va < end_va; ) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(reinterpret_cast<LPCVOID>(page_va), &mbi, sizeof(mbi)) == 0) break;
        uint64_t reg_end = (std::min)(end_va, reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize);
        if (mbi.State == MEM_FREE) {
            ::VirtualAlloc(reinterpret_cast<LPVOID>(page_va), static_cast<SIZE_T>(reg_end - page_va),
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        } else if (mbi.State == MEM_RESERVE) {
            ::VirtualAlloc(reinterpret_cast<LPVOID>(page_va), static_cast<SIZE_T>(reg_end - page_va),
                           MEM_COMMIT, PAGE_READWRITE);
        } else if (mbi.Protect & (PAGE_NOACCESS | PAGE_READONLY)) {
            DWORD old_prot = 0;
            ::VirtualProtect(reinterpret_cast<LPVOID>(page_va), static_cast<SIZE_T>(reg_end - page_va),
                             PAGE_READWRITE, &old_prot);
        }
        page_va = (reg_end > page_va) ? reg_end : (page_va + 0x10000ULL);
    }
#endif
    ifs.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    ifs.read(reinterpret_cast<char*>(dst_buf), static_cast<std::streamsize>(length));
    return static_cast<int64_t>(ifs.gcount());
}

} // namespace yotei::kernel
