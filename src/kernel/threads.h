#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yotei::kernel {

struct SceProcParam {
    uint64_t size;
    uint32_t magic;           // "ORBI" (0x4942524F)
    uint32_t entry_count;     // 5
    uint32_t sdk_version;     // e.g. 0x09040001
    uint32_t compiler_version;
    uint64_t main_thread_prio;
    uint64_t main_thread_stack_size;
    uint64_t libc_param_addr;
};

struct GuestThread {
    uint64_t thread_id = 0;
    std::string name;
#ifdef _WIN32
    HANDLE win_handle = nullptr;
    DWORD win_tid = 0;
#endif
    uint64_t entry_fn = 0;
    uint64_t arg = 0;
    uint64_t stack_size = 0;
    uint64_t stack_base = 0;
    uint64_t tcb_address = 0;
    void* tls_memory = nullptr;
    uint64_t return_value = 0;
    bool is_main_thread = false;
    bool is_finished = false;
    bool is_detached = false;
};

class ThreadManager {
public:
    static ThreadManager& Instance();

    void Initialize(uint64_t tls_template_vaddr, const uint8_t* tls_data,
                    size_t filesz, size_t memsz, size_t align);

    bool SetupMainThread();

    uint64_t AllocateThreadTls(uint64_t thread_id, void** out_mem_ptr);
    void SetCurrentThreadTls(uint64_t tcb_address);
    uint64_t GetCurrentThreadTcb() const;

    uint64_t CreateThread(uint64_t* out_thread_id, uint64_t attr_addr,
                          uint64_t entry_fn, uint64_t arg);
    uint64_t JoinThread(uint64_t thread_id, uint64_t* out_retval);
    void ExitThread(uint64_t retval);
    uint64_t GetCurrentGuestThreadId();

    // Mutex
    uint32_t MutexInit(uint64_t mutex_addr, uint64_t attr_addr);
    uint32_t MutexLock(uint64_t mutex_addr);
    uint32_t MutexTrylock(uint64_t mutex_addr);
    uint32_t MutexUnlock(uint64_t mutex_addr);
    uint32_t MutexDestroy(uint64_t mutex_addr);

    // CondVar
    uint32_t CondInit(uint64_t cond_addr, uint64_t attr_addr);
    uint32_t CondWait(uint64_t cond_addr, uint64_t mutex_addr);
    uint32_t CondTimedwait(uint64_t cond_addr, uint64_t mutex_addr, uint64_t usec);
    uint32_t CondSignal(uint64_t cond_addr);
    uint32_t CondBroadcast(uint64_t cond_addr);
    uint32_t CondDestroy(uint64_t cond_addr);

    // Semaphore
    int32_t SemaCreate(uint64_t out_sem_addr, const char* name, uint32_t attr, int32_t init_count, int32_t max_count);
    int32_t SemaWait(int32_t sem_id, int32_t count, uint32_t* timeout);
    int32_t SemaSignal(int32_t sem_id, int32_t count);
    int32_t SemaDelete(int32_t sem_id);

    // RWLock
    uint32_t RwlockInit(uint64_t rwlock_addr, uint64_t attr_addr);
    uint32_t RwlockRdlock(uint64_t rwlock_addr);
    uint32_t RwlockWrlock(uint64_t rwlock_addr);
    uint32_t RwlockUnlock(uint64_t rwlock_addr);
    uint32_t RwlockDestroy(uint64_t rwlock_addr);

    // ProcParam parsing
    bool ParseProcParam(const uint8_t* data, size_t size, SceProcParam* out_param);

    // Dynamic HLE NID dispatcher for all threading & sync calls
    bool DispatchNid(const std::string& nid, const std::string& name,
                     uint64_t rdi, uint64_t rsi, uint64_t rdx,
                     uint64_t rcx, uint64_t r8, uint64_t r9,
                     uint64_t* ret);

    size_t GetActiveThreadCount();
    void Shutdown();

private:
    ThreadManager() = default;
    ~ThreadManager();

    std::vector<uint8_t> tls_template_;
    size_t tls_filesz_ = 0;
    size_t tls_memsz_ = 0;
    size_t tls_align_ = 16;
    uint64_t tls_template_vaddr_ = 0;

    mutable std::mutex thread_lock_;
    std::unordered_map<uint64_t, std::shared_ptr<GuestThread>> threads_;
    uint64_t next_thread_id_ = 1;

    mutable std::mutex sync_lock_;
    std::unordered_map<uint64_t, std::unique_ptr<std::recursive_mutex>> mutexes_;
    std::unordered_map<uint64_t, std::unique_ptr<std::shared_mutex>> rwlocks_;
    std::unordered_map<uint64_t, std::unique_ptr<std::condition_variable_any>> conds_;
    std::unordered_map<int32_t, void*> semaphores_;
    int32_t next_sem_id_ = 100;
};

// Helper for invoking a guest SysV AMD64 function from host
uint64_t InvokeGuestSysV(uint64_t fn_addr, uint64_t rdi_arg, uint64_t rsi_arg,
                         uint64_t rdx_arg = 0, uint64_t rcx_arg = 0);

} // namespace yotei::kernel
