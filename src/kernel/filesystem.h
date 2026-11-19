#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yotei::kernel {

#pragma pack(push, 1)
struct SceKernelStat {
    uint32_t st_dev;
    uint32_t st_ino;
    uint16_t st_mode;
    uint16_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t st_rdev;
    int64_t  st_atime_sec;
    int64_t  st_atime_nsec;
    int64_t  st_mtime_sec;
    int64_t  st_mtime_nsec;
    int64_t  st_ctime_sec;
    int64_t  st_ctime_nsec;
    int64_t  st_size;
    int64_t  st_blocks;
    uint32_t st_blksize;
    uint32_t st_flags;
    uint32_t st_gen;
    int32_t  st_lspare;
    int64_t  st_birthtime_sec;
    int64_t  st_birthtime_nsec;
};
#pragma pack(pop)

struct AmprIndexEntry {
    uint64_t path_hash;
    uint64_t file_size;
    std::string virtual_path;
    std::string mount_point;
    uint32_t apr_file_id;
};

class VirtualFileSystem {
public:
    static VirtualFileSystem& Instance();

    void Mount(const std::string& guest_prefix, const std::filesystem::path& host_dir);
    std::filesystem::path ResolveGuestPath(const std::string& guest_path) const;

    // Load and parse /app0/ampr_emu.index (AMPRIDX3 format, 105,803 entries)
    bool LoadAmprIndex(const std::filesystem::path& index_path);

    // Prospero libkernel file operations
    int32_t Open(const char* guest_path, int32_t flags, int32_t mode);
    int32_t Close(int32_t fd);
    int64_t Read(int32_t fd, void* buf, uint64_t count);
    int64_t Pread(int32_t fd, void* buf, uint64_t count, int64_t offset);
    int32_t Stat(const char* guest_path, SceKernelStat* sb);
    int32_t Fstat(int32_t fd, SceKernelStat* sb);

    // Prospero APR / AMPR file resolution (sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach)
    int32_t AprResolvePath(const std::string& virtual_path, uint32_t* out_id, uint64_t* out_size) const;
    int64_t AprReadFileById(uint32_t file_id, void* dst_buf, uint64_t length, uint64_t offset) const;

    size_t GetAmprEntryCount() const { return ampr_by_id_.size(); }

private:
    VirtualFileSystem() = default;

    struct OpenFileHandle {
        std::filesystem::path host_path;
        std::shared_ptr<std::ifstream> stream;
        uint64_t file_size = 0;
        bool is_directory = false;
    };

    mutable std::mutex mutex_;
    std::vector<std::pair<std::string, std::filesystem::path>> mounts_;
    std::unordered_map<int32_t, OpenFileHandle> open_fds_;
    int32_t next_fd_ = 100;

    std::unordered_map<std::string, AmprIndexEntry> ampr_by_path_;
    std::unordered_map<uint32_t, AmprIndexEntry> ampr_by_id_;
};

} // namespace yotei::kernel
