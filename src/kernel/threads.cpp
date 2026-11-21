#include "threads.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>

#ifdef _WIN32
#include <immintrin.h>
#endif

namespace yotei::kernel {

namespace {

#ifdef _WIN32
thread_local uint64_t g_current_tcb = 0;
thread_local uint64_t g_current_guest_tid = 1;

DWORD WINAPI GuestThreadEntry(LPVOID param) {
    auto* th = reinterpret_cast<GuestThread*>(param);
    if (!th) return 1;

    g_current_tcb = th->tcb_address;
    g_current_guest_tid = th->thread_id;
    ThreadManager::Instance().SetCurrentThreadTls(th->tcb_address);

    {
        static std::mutex g_thread_log_lock;
        std::lock_guard<std::mutex> log_lock(g_thread_log_lock);
        std::cout << "  [THREAD] Started Guest Thread ID=" << th->thread_id
                  << " ('" << th->name << "') Entry=0x" << std::hex << th->entry_fn
                  << " Arg=0x" << th->arg << std::dec << "\n" << std::flush;
    }

    th->return_value = InvokeGuestSysV(th->entry_fn, th->arg, 0, 0, 0);

    th->is_finished = true;
    std::cout << "  [THREAD] Finished Guest Thread ID=" << th->thread_id
              << " Return=0x" << std::hex << th->return_value << std::dec << "\n" << std::flush;
    return 0;
}
#endif

} // namespace

uint64_t InvokeGuestSysV(uint64_t fn_addr, uint64_t rdi_arg, uint64_t rsi_arg,
                         uint64_t rdx_arg, uint64_t rcx_arg) {
#ifdef _WIN32
    // Windows MS x64 to SysV x86-64 caller trampoline:
    // Arguments passed from host:
    //   rcx: fn_addr
    //   rdx: rdi_arg
    //   r8 : rsi_arg
    //   r9 : rdx_arg
    //   [rsp + 0x28]: rcx_arg
    static uint8_t caller_code[] = {
        0x55,                                     // push rbp
        0x48, 0x89, 0xE5,                         // mov rbp, rsp
        0x41, 0x57,                               // push r15
        0x41, 0x56,                               // push r14
        0x41, 0x55,                               // push r13
        0x41, 0x54,                               // push r12
        0x57,                                     // push rdi
        0x56,                                     // push rsi
        0x53,                                     // push rbx
        0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 40 (16-byte align + shadow space)
        0x49, 0x89, 0xCA,                         // mov r10, rcx (fn_addr)
        0x48, 0x89, 0xD7,                         // mov rdi, rdx (arg0)
        0x4C, 0x89, 0xC6,                         // mov rsi, r8  (arg1)
        0x4D, 0x89, 0xCA,                         // mov r10, r9 -> wait:
        0x48, 0x89, 0xCA,                         // mov rdx, rcx
        0x48, 0x8B, 0x4D, 0x30,                   // mov rcx, [rbp + 48] (rcx_arg)
        0x48, 0x89, 0xDA,                         // mov rdx, rbx...
        0x41, 0xFF, 0xD2,                         // call r10
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
    // Direct robust C++ assembly gate using static allocated buffer
    static void* exec_mem = nullptr;
    if (!exec_mem) {
        // Precise MSx64 -> SysV x86-64 adapter code
        uint8_t precise_adapter[] = {
            0x55,                                           // push rbp
            0x48, 0x89, 0xE5,                               // mov rbp, rsp
            0x41, 0x57,                                     // push r15
            0x41, 0x56,                                     // push r14
            0x41, 0x55,                                     // push r13
            0x41, 0x54,                                     // push r12
            0x57,                                           // push rdi
            0x56,                                           // push rsi
            0x53,                                           // push rbx
            0x48, 0x83, 0xEC, 0x18,                         // sub rsp, 24 (align to 16-byte boundary)
            0x49, 0x89, 0xCF,                               // mov r15, rcx (fn_addr)
            0x48, 0x89, 0xD7,                               // mov rdi, rdx (rdi_arg)
            0x4C, 0x89, 0xC6,                               // mov rsi, r8  (rsi_arg)
            0x4D, 0x89, 0xCA,                               // mov r10, r9  (rdx_arg)
            0x4C, 0x8B, 0x5D, 0x30,                         // mov r11, [rbp + 48] (rcx_arg)
            0x49, 0x89, 0xD2,                               // mov rdx, r10 (SysV arg2 in rdx)
            0x49, 0x89, 0xD9,                               // mov rcx, r11 (SysV arg3 in rcx)
            0x41, 0xFF, 0xD7,                               // call r15
            0x48, 0x8D, 0x65, 0xC8,                         // lea rsp, [rbp - 56]
            0x5B,                                           // pop rbx
            0x5E,                                           // pop rsi
            0x5F,                                           // pop rdi
            0x41, 0x5C,                                     // pop r12
            0x41, 0x5D,                                     // pop r13
            0x41, 0x5E,                                     // pop r14
            0x41, 0x5F,                                     // pop r15
            0x5D,                                           // pop rbp
            0xC3                                            // ret
        };
        exec_mem = VirtualAlloc(nullptr, sizeof(precise_adapter), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        std::memcpy(exec_mem, precise_adapter, sizeof(precise_adapter));
    }
    using GateFn = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    auto gate = reinterpret_cast<GateFn>(exec_mem);
    if (g_current_tcb) {
        _writefsbase_u64(g_current_tcb);
    }
    return gate(fn_addr, rdi_arg, rsi_arg, rdx_arg, rcx_arg);
#else
    return 0;
#endif
}

ThreadManager& ThreadManager::Instance() {
    static ThreadManager inst;
    return inst;
}

ThreadManager::~ThreadManager() {
    Shutdown();
}

void ThreadManager::Initialize(uint64_t tls_template_vaddr, const uint8_t* tls_data,
                               size_t filesz, size_t memsz, size_t align) {
    tls_template_vaddr_ = tls_template_vaddr;
    tls_filesz_ = filesz;
    tls_memsz_ = memsz;
    tls_align_ = (align < 16) ? 16 : align;

    if (tls_data && filesz > 0) {
        tls_template_.assign(tls_data, tls_data + filesz);
    }
}

uint64_t ThreadManager::AllocateThreadTls(uint64_t thread_id, void** out_mem_ptr) {
#ifdef _WIN32
    // Allocate 8 KiB page for Thread TLS and TCB
    const size_t alloc_sz = 8192;
    void* mem = VirtualAlloc(nullptr, alloc_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 0;

    std::memset(mem, 0, alloc_sz);
    if (out_mem_ptr) *out_mem_ptr = mem;

    uint8_t* base = reinterpret_cast<uint8_t*>(mem);

    // Layout Variant II for AMD64:
    // [0 .. 4096): Static TLS storage
    // [4096]: TCB
    // Static TLS block is aligned up to 16 bytes:
    size_t tls_aligned = (tls_memsz_ + (tls_align_ - 1)) & ~(tls_align_ - 1);
    if (tls_aligned == 0) tls_aligned = 0x190;

    uint8_t* tcb = base + 4096;
    uint8_t* tls_data_start = tcb - tls_aligned;

    // Copy initialized .tdata
    if (!tls_template_.empty() && tls_filesz_ > 0) {
        std::memcpy(tls_data_start, tls_template_.data(), (std::min)(tls_filesz_, tls_aligned));
    }

    // Set up TCB:
    // Offset 0: Pointer to itself (self-pointer for %fs:[0])
    *reinterpret_cast<uint64_t*>(tcb + 0) = reinterpret_cast<uint64_t>(tcb);
    // Offset 8: DTV pointer
    *reinterpret_cast<uint64_t*>(tcb + 8) = reinterpret_cast<uint64_t>(tcb + 0x200);
    // Offset 16: Thread ID
    *reinterpret_cast<uint64_t*>(tcb + 16) = thread_id;

    // DTV setup at tcb + 0x200
    uint64_t* dtv = reinterpret_cast<uint64_t*>(tcb + 0x200);
    dtv[0] = 1;                                            // generation count
    dtv[1] = reinterpret_cast<uint64_t>(tls_data_start);  // module 1 TLS block base

    return reinterpret_cast<uint64_t>(tcb);
#else
    return 0;
#endif
}

void ThreadManager::SetCurrentThreadTls(uint64_t tcb_address) {
#ifdef _WIN32
    g_current_tcb = tcb_address;
    _writefsbase_u64(tcb_address);
#endif
}

uint64_t ThreadManager::GetCurrentThreadTcb() const {
#ifdef _WIN32
    return g_current_tcb;
#else
    return 0;
#endif
}

uint64_t ThreadManager::GetCurrentGuestThreadId() {
#ifdef _WIN32
    return g_current_guest_tid;
#else
    return 1;
#endif
}

bool ThreadManager::SetupMainThread() {
    std::lock_guard<std::mutex> lock(thread_lock_);

    auto main_th = std::make_shared<GuestThread>();
    main_th->thread_id = 1;
    main_th->name = "MainThread";
    main_th->is_main_thread = true;

    void* tls_mem = nullptr;
    main_th->tcb_address = AllocateThreadTls(1, &tls_mem);
    main_th->tls_memory = tls_mem;

    if (!main_th->tcb_address) {
        std::cerr << "[!] Failed to allocate Main Thread TLS block\n";
        return false;
    }

    SetCurrentThreadTls(main_th->tcb_address);
    threads_[1] = main_th;

    std::cout << "[+] Configured Main Guest Thread:\n"
              << "    Thread ID         : 1\n"
              << "    FS Base (TCB)     : 0x" << std::hex << main_th->tcb_address << "\n"
              << "    Static TLS Base   : 0x" << (main_th->tcb_address - 0x190) << std::dec << "\n"
              << "    Self-Pointer      : 0x" << std::hex
              << *reinterpret_cast<uint64_t*>(main_th->tcb_address) << std::dec << "\n";
    return true;
}

uint64_t ThreadManager::CreateThread(uint64_t* out_thread_id, uint64_t attr_addr,
                                     uint64_t entry_fn, uint64_t arg) {
    std::lock_guard<std::mutex> lock(thread_lock_);
    uint64_t tid = ++next_thread_id_;

    auto th = std::make_shared<GuestThread>();
    th->thread_id = tid;
    th->entry_fn = entry_fn;
    th->arg = arg;
    th->name = "Worker_" + std::to_string(tid);

    void* tls_mem = nullptr;
    th->tcb_address = AllocateThreadTls(tid, &tls_mem);
    th->tls_memory = tls_mem;

#ifdef _WIN32
    DWORD win_tid = 0;
    HANDLE h = ::CreateThread(nullptr, 0x40000, GuestThreadEntry, th.get(), 0, &win_tid);
    if (!h) {
        std::cerr << "[!] Failed to spawn Win32 thread for Guest TID=" << tid << "\n";
        return 0x8002000C; // ENOMEM
    }
    th->win_handle = h;
    th->win_tid = win_tid;
#endif

    threads_[tid] = th;
    if (out_thread_id && reinterpret_cast<uintptr_t>(out_thread_id) >= 0x1000) {
        *out_thread_id = tid;
    }
    return 0;
}

uint64_t ThreadManager::JoinThread(uint64_t thread_id, uint64_t* out_retval) {
    std::shared_ptr<GuestThread> target;
    {
        std::lock_guard<std::mutex> lock(thread_lock_);
        auto it = threads_.find(thread_id);
        if (it == threads_.end()) return 0x80020003; // ESRCH
        target = it->second;
    }

#ifdef _WIN32
    if (target->win_handle) {
        ::WaitForSingleObject(target->win_handle, INFINITE);
        ::CloseHandle(target->win_handle);
        target->win_handle = nullptr;
    }
#endif

    if (out_retval && reinterpret_cast<uintptr_t>(out_retval) >= 0x1000) {
        *out_retval = target->return_value;
    }
    return 0;
}

void ThreadManager::ExitThread(uint64_t retval) {
#ifdef _WIN32
    ::ExitThread(static_cast<DWORD>(retval));
#endif
}

size_t ThreadManager::GetActiveThreadCount() {
    std::lock_guard<std::mutex> lock(thread_lock_);
    return threads_.size();
}

void ThreadManager::Shutdown() {
    std::lock_guard<std::mutex> lock(thread_lock_);
#ifdef _WIN32
    for (auto& [tid, th] : threads_) {
        if (th->win_handle) {
            DWORD wait_res = ::WaitForSingleObject(th->win_handle, 100);
            if (wait_res == WAIT_TIMEOUT) {
                ::TerminateThread(th->win_handle, 0);
            }
            ::CloseHandle(th->win_handle);
            th->win_handle = nullptr;
        }
        if (th->tls_memory) {
            ::VirtualFree(th->tls_memory, 0, MEM_RELEASE);
            th->tls_memory = nullptr;
        }
    }
#endif
    threads_.clear();

    std::lock_guard<std::mutex> slock(sync_lock_);
    mutexes_.clear();
    rwlocks_.clear();
    conds_.clear();
#ifdef _WIN32
    for (auto& [id, h] : semaphores_) {
        if (h) ::CloseHandle(static_cast<HANDLE>(h));
    }
#endif
    semaphores_.clear();
}

// Mutex API
uint32_t ThreadManager::MutexInit(uint64_t mutex_addr, uint64_t) {
    if (!mutex_addr) return 0x80020016; // EINVAL
    std::lock_guard<std::mutex> lock(sync_lock_);
    mutexes_[mutex_addr] = std::make_unique<std::recursive_mutex>();
    *reinterpret_cast<uint64_t*>(mutex_addr) = mutex_addr;
    return 0;
}

uint32_t ThreadManager::MutexLock(uint64_t mutex_addr) {
    if (!mutex_addr) return 0x80020016;
    std::recursive_mutex* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = mutexes_.find(mutex_addr);
        if (it == mutexes_.end()) {
            mutexes_[mutex_addr] = std::make_unique<std::recursive_mutex>();
            m = mutexes_[mutex_addr].get();
        } else {
            m = it->second.get();
        }
    }
    m->lock();
    return 0;
}

uint32_t ThreadManager::MutexTrylock(uint64_t mutex_addr) {
    if (!mutex_addr) return 0x80020016;
    std::recursive_mutex* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = mutexes_.find(mutex_addr);
        if (it == mutexes_.end()) {
            mutexes_[mutex_addr] = std::make_unique<std::recursive_mutex>();
            m = mutexes_[mutex_addr].get();
        } else {
            m = it->second.get();
        }
    }
    return m->try_lock() ? 0 : 0x80020010; // EBUSY
}

uint32_t ThreadManager::MutexUnlock(uint64_t mutex_addr) {
    if (!mutex_addr) return 0x80020016;
    std::recursive_mutex* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = mutexes_.find(mutex_addr);
        if (it != mutexes_.end()) {
            m = it->second.get();
        }
    }
    if (m) m->unlock();
    return 0;
}

uint32_t ThreadManager::MutexDestroy(uint64_t mutex_addr) {
    if (!mutex_addr) return 0x80020016;
    std::lock_guard<std::mutex> lock(sync_lock_);
    mutexes_.erase(mutex_addr);
    return 0;
}

// CondVar API
uint32_t ThreadManager::CondInit(uint64_t cond_addr, uint64_t) {
    if (!cond_addr) return 0x80020016;
    std::lock_guard<std::mutex> lock(sync_lock_);
    conds_[cond_addr] = std::make_unique<std::condition_variable_any>();
    *reinterpret_cast<uint64_t*>(cond_addr) = cond_addr;
    return 0;
}

uint32_t ThreadManager::CondWait(uint64_t cond_addr, uint64_t mutex_addr) {
    if (!cond_addr || !mutex_addr) return 0x80020016;
    std::condition_variable_any* cv = nullptr;
    std::recursive_mutex* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it_c = conds_.find(cond_addr);
        if (it_c == conds_.end()) {
            conds_[cond_addr] = std::make_unique<std::condition_variable_any>();
            cv = conds_[cond_addr].get();
        } else {
            cv = it_c->second.get();
        }
        auto it_m = mutexes_.find(mutex_addr);
        if (it_m == mutexes_.end()) {
            mutexes_[mutex_addr] = std::make_unique<std::recursive_mutex>();
            m = mutexes_[mutex_addr].get();
        } else {
            m = it_m->second.get();
        }
    }
    if (cv && m) {
        cv->wait(*m);
    }
    return 0;
}

uint32_t ThreadManager::CondTimedwait(uint64_t cond_addr, uint64_t mutex_addr, uint64_t usec) {
    if (!cond_addr || !mutex_addr) return 0x80020016;
    std::condition_variable_any* cv = nullptr;
    std::recursive_mutex* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it_c = conds_.find(cond_addr);
        if (it_c == conds_.end()) {
            conds_[cond_addr] = std::make_unique<std::condition_variable_any>();
            cv = conds_[cond_addr].get();
        } else {
            cv = it_c->second.get();
        }
        auto it_m = mutexes_.find(mutex_addr);
        if (it_m == mutexes_.end()) {
            mutexes_[mutex_addr] = std::make_unique<std::recursive_mutex>();
            m = mutexes_[mutex_addr].get();
        } else {
            m = it_m->second.get();
        }
    }
    if (cv && m) {
        uint64_t wait_usec = (std::min)(usec, 5000000ULL);
        auto res = cv->wait_for(*m, std::chrono::microseconds(wait_usec));
        return (res == std::cv_status::timeout) ? 0x8002003C : 0; // ETIMEDOUT
    }
    return 0;
}

uint32_t ThreadManager::CondSignal(uint64_t cond_addr) {
    if (!cond_addr) return 0x80020016;
    std::lock_guard<std::mutex> lock(sync_lock_);
    auto it = conds_.find(cond_addr);
    if (it != conds_.end()) {
        it->second->notify_one();
    }
    return 0;
}

uint32_t ThreadManager::CondBroadcast(uint64_t cond_addr) {
    if (!cond_addr) return 0x80020016;
    std::lock_guard<std::mutex> lock(sync_lock_);
    auto it = conds_.find(cond_addr);
    if (it != conds_.end()) {
        it->second->notify_all();
    }
    return 0;
}

uint32_t ThreadManager::CondDestroy(uint64_t cond_addr) {
    if (!cond_addr) return 0x80020016;
    std::lock_guard<std::mutex> lock(sync_lock_);
    conds_.erase(cond_addr);
    return 0;
}

// Semaphore API
int32_t ThreadManager::SemaCreate(uint64_t out_sem_addr, const char*, uint32_t, int32_t init_count, int32_t max_count) {
    std::lock_guard<std::mutex> lock(sync_lock_);
    int32_t id = ++next_sem_id_;
    if (init_count < 0) init_count = 0;
    if (max_count <= 0) max_count = 255;
    if (init_count > max_count) init_count = max_count;
#ifdef _WIN32
    HANDLE h = ::CreateSemaphoreW(nullptr, init_count, max_count, nullptr);
    semaphores_[id] = h;
#endif
    if (out_sem_addr >= 0x1000) {
        *reinterpret_cast<uint64_t*>(out_sem_addr) = static_cast<uint64_t>(id);
    }
    return 0; // SCE_OK
}

int32_t ThreadManager::SemaWait(int32_t sem_id, int32_t count, uint32_t* timeout) {
    HANDLE h = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = semaphores_.find(sem_id);
        if (it != semaphores_.end()) h = static_cast<HANDLE>(it->second);
    }
    if (!h) {
#ifdef _WIN32
        ::Sleep(1);
#endif
        return 0;
    }
#ifdef _WIN32
    DWORD wait_ms = 250; // Bounded wait quantum so worker threads stay responsive to shutdown
    if (timeout && reinterpret_cast<uintptr_t>(timeout) >= 0x1000) {
        wait_ms = (std::min)(static_cast<DWORD>(*timeout / 1000), 250UL);
    }
    if (count <= 0) count = 1;
    for (int32_t i = 0; i < count; ++i) {
        ::WaitForSingleObject(h, wait_ms);
    }
#endif
    return 0;
}

int32_t ThreadManager::SemaSignal(int32_t sem_id, int32_t count) {
    HANDLE h = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = semaphores_.find(sem_id);
        if (it != semaphores_.end()) h = static_cast<HANDLE>(it->second);
    }
    if (!h) return -1;
#ifdef _WIN32
    ::ReleaseSemaphore(h, count, nullptr);
#endif
    return 0;
}

int32_t ThreadManager::SemaDelete(int32_t sem_id) {
    std::lock_guard<std::mutex> lock(sync_lock_);
    auto it = semaphores_.find(sem_id);
    if (it != semaphores_.end()) {
#ifdef _WIN32
        if (it->second) ::CloseHandle(static_cast<HANDLE>(it->second));
#endif
        semaphores_.erase(it);
    }
    return 0;
}

// RWLock API
uint32_t ThreadManager::RwlockInit(uint64_t rwlock_addr, uint64_t) {
    if (!rwlock_addr) return 0x80020016;
    std::lock_guard<std::mutex> lock(sync_lock_);
    rwlocks_[rwlock_addr] = std::make_unique<std::shared_mutex>();
    return 0;
}

uint32_t ThreadManager::RwlockRdlock(uint64_t rwlock_addr) {
    if (!rwlock_addr) return 0x80020016;
    std::shared_mutex* rw = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = rwlocks_.find(rwlock_addr);
        if (it == rwlocks_.end()) {
            rwlocks_[rwlock_addr] = std::make_unique<std::shared_mutex>();
            rw = rwlocks_[rwlock_addr].get();
        } else {
            rw = it->second.get();
        }
    }
    rw->lock_shared();
    return 0;
}

uint32_t ThreadManager::RwlockWrlock(uint64_t rwlock_addr) {
    if (!rwlock_addr) return 0x80020016;
    std::shared_mutex* rw = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = rwlocks_.find(rwlock_addr);
        if (it == rwlocks_.end()) {
            rwlocks_[rwlock_addr] = std::make_unique<std::shared_mutex>();
            rw = rwlocks_[rwlock_addr].get();
        } else {
            rw = it->second.get();
        }
    }
    rw->lock();
    return 0;
}

uint32_t ThreadManager::RwlockUnlock(uint64_t rwlock_addr) {
    if (!rwlock_addr) return 0x80020016;
    std::shared_mutex* rw = nullptr;
    {
        std::lock_guard<std::mutex> lock(sync_lock_);
        auto it = rwlocks_.find(rwlock_addr);
        if (it != rwlocks_.end()) rw = it->second.get();
    }
    if (rw) {
        // Unlock shared or exclusive: unlock() handles write lock, unlock_shared handles read lock
        rw->unlock();
    }
    return 0;
}

uint32_t ThreadManager::RwlockDestroy(uint64_t rwlock_addr) {
    if (!rwlock_addr) return 0x80020016;
    std::lock_guard<std::mutex> lock(sync_lock_);
    rwlocks_.erase(rwlock_addr);
    return 0;
}

bool ThreadManager::ParseProcParam(const uint8_t* data, size_t size, SceProcParam* out_param) {
    if (!data || size < 0x20 || !out_param) return false;
    out_param->size = *reinterpret_cast<const uint64_t*>(data);
    out_param->magic = *reinterpret_cast<const uint32_t*>(data + 8);
    out_param->entry_count = *reinterpret_cast<const uint32_t*>(data + 12);
    out_param->sdk_version = *reinterpret_cast<const uint32_t*>(data + 16);
    out_param->compiler_version = *reinterpret_cast<const uint32_t*>(data + 20);
    if (size >= 0x40) {
        out_param->main_thread_prio = *reinterpret_cast<const uint64_t*>(data + 24);
        out_param->main_thread_stack_size = *reinterpret_cast<const uint64_t*>(data + 32);
        out_param->libc_param_addr = *reinterpret_cast<const uint64_t*>(data + 40);
    }
    return (out_param->magic == 0x4942524F); // 'ORBI'
}

bool ThreadManager::DispatchNid(const std::string& nid, const std::string& name,
                                uint64_t rdi, uint64_t rsi, uint64_t rdx,
                                uint64_t rcx, uint64_t r8, uint64_t r9,
                                uint64_t* ret) {
    if (!ret) return false;

    // Threads
    if (nid == "aI+OeCz8xrQ" || name == "scePthreadSelf") {
        *ret = GetCurrentGuestThreadId();
        return true;
    }
    if (nid == "EI-5-jlq2dE" || name == "scePthreadGetthreadid") {
        *ret = GetCurrentGuestThreadId();
        return true;
    }
    if (nid == "6UgtwV+0zb4" || name == "scePthreadCreate") {
        *ret = CreateThread(reinterpret_cast<uint64_t*>(rdi), rsi, rdx, rcx);
        return true;
    }
    if (nid == "onNY9Byn-W8" || name == "scePthreadJoin") {
        *ret = JoinThread(rdi, reinterpret_cast<uint64_t*>(rsi));
        return true;
    }
    if (nid == "3kg7rT0NQIs" || name == "scePthreadExit") {
        ExitThread(rdi);
        *ret = 0;
        return true;
    }
    if (nid == "3PtV6p3QNX4" || name == "scePthreadEqual") {
        *ret = (rdi == rsi) ? 1 : 0;
        return true;
    }

    // Thread Attributes
    if (nid == "nsYoNRywwNg" || name == "scePthreadAttrInit" ||
        nid == "62KCwEMmzcM" || name == "scePthreadAttrDestroy" ||
        nid == "UTXzJbWhhTE" || name == "scePthreadAttrSetstacksize" ||
        nid == "3qxgM4ezETA" || name == "scePthreadAttrSetaffinity" ||
        nid == "-Wreprtu0Qs" || name == "scePthreadAttrSetdetachstate" ||
        nid == "eXbUSpEaTsA" || name == "scePthreadAttrSetinheritsched" ||
        nid == "DzES9hQF4f4" || name == "scePthreadAttrSetschedparam" ||
        nid == "x1X76arYMxU" || name == "scePthreadAttrGet" ||
        nid == "Ru36fiTtJzA" || name == "scePthreadAttrGetstackaddr") {
        *ret = 0;
        return true;
    }

    // Priority & Affinity
    if (nid == "1tKyG7RlMJo" || name == "scePthreadGetprio") {
        if (rsi && rsi >= 0x1000) *reinterpret_cast<uint32_t*>(rsi) = 256;
        *ret = 0;
        return true;
    }
    if (nid == "W0Hpm2X0uPE" || name == "scePthreadSetprio" ||
        nid == "bt3CTBKmGyI" || name == "scePthreadSetaffinity" ||
        nid == "rcrVFJsQWRY" || name == "scePthreadGetaffinity") {
        *ret = 0;
        return true;
    }

    // Mutex Attributes
    if (nid == "F8bUHwAG284" || name == "scePthreadMutexattrInit" ||
        nid == "smWEktiyyG0" || name == "scePthreadMutexattrDestroy" ||
        nid == "iMp8QpE+XO4" || name == "scePthreadMutexattrSettype" ||
        nid == "1FGvU0i9saQ" || name == "scePthreadMutexattrSetprotocol") {
        *ret = 0;
        return true;
    }

    // Mutex Operations
    if (nid == "cmo1RIYva9o" || name == "scePthreadMutexInit") {
        *ret = MutexInit(rdi, rsi);
        return true;
    }
    if (nid == "9UK1vLZQft4" || name == "scePthreadMutexLock") {
        *ret = MutexLock(rdi);
        return true;
    }
    if (nid == "upoVrzMHFeE" || name == "scePthreadMutexTrylock") {
        *ret = MutexTrylock(rdi);
        return true;
    }
    if (nid == "IafI2PxcPnQ" || name == "scePthreadMutexTimedlock") {
        // Timedlock: simplified to trylock
        *ret = MutexTrylock(rdi);
        return true;
    }
    if (nid == "tn3VlD0hG60" || name == "scePthreadMutexUnlock") {
        *ret = MutexUnlock(rdi);
        return true;
    }
    if (nid == "2Of0f+3mhhE" || name == "scePthreadMutexDestroy") {
        *ret = MutexDestroy(rdi);
        return true;
    }

    // CondVar Attributes
    if (nid == "m5-2bsNfv7s" || name == "scePthreadCondattrInit" ||
        nid == "waPcxYiR3WA" || name == "scePthreadCondattrDestroy") {
        *ret = 0;
        return true;
    }

    // CondVar Operations
    if (nid == "2Tb92quprl0" || name == "scePthreadCondInit") {
        *ret = CondInit(rdi, rsi);
        return true;
    }
    if (nid == "WKAXJ4XBPQ4" || name == "scePthreadCondWait") {
        *ret = CondWait(rdi, rsi);
        return true;
    }
    if (nid == "BmMjYxmew1w" || name == "scePthreadCondTimedwait") {
        *ret = CondTimedwait(rdi, rsi, rdx);
        return true;
    }
    if (nid == "kDh-NfxgMtE" || name == "scePthreadCondSignal") {
        *ret = CondSignal(rdi);
        return true;
    }
    if (nid == "JGgj7Uvrl+A" || name == "scePthreadCondBroadcast") {
        *ret = CondBroadcast(rdi);
        return true;
    }
    if (nid == "g+PZd2hiacg" || name == "scePthreadCondDestroy") {
        *ret = CondDestroy(rdi);
        return true;
    }

    // Semaphores
    if (nid == "188x57JYp0g" || name == "sceKernelCreateSema") {
        *ret = static_cast<uint64_t>(SemaCreate(
            rdi,
            (rsi >= 0x1000) ? reinterpret_cast<const char*>(rsi) : "Sema",
            static_cast<uint32_t>(rdx),
            static_cast<int32_t>(rcx),
            static_cast<int32_t>(r8)));
        return true;
    }
    if (nid == "Zxa0VhQVTsk" || name == "sceKernelWaitSema") {
        *ret = static_cast<uint64_t>(SemaWait(static_cast<int32_t>(rdi),
                                              static_cast<int32_t>(rsi),
                                              reinterpret_cast<uint32_t*>(rdx)));
        return true;
    }
    if (nid == "4czppHBiriw" || name == "sceKernelSignalSema") {
        *ret = static_cast<uint64_t>(SemaSignal(static_cast<int32_t>(rdi),
                                                static_cast<int32_t>(rsi)));
        return true;
    }
    if (nid == "R1Jvn8bSCW8" || name == "sceKernelDeleteSema") {
        *ret = static_cast<uint64_t>(SemaDelete(static_cast<int32_t>(rdi)));
        return true;
    }

    // RWLocks
    if (nid == "6ULAa0fq4jA" || name == "scePthreadRwlockInit") {
        *ret = RwlockInit(rdi, rsi);
        return true;
    }
    if (nid == "Ox9i0c7L5w0" || name == "scePthreadRwlockRdlock") {
        *ret = RwlockRdlock(rdi);
        return true;
    }
    if (nid == "mqdNorrB+gI" || name == "scePthreadRwlockWrlock") {
        *ret = RwlockWrlock(rdi);
        return true;
    }
    if (nid == "+L98PIbGttk" || name == "scePthreadRwlockUnlock") {
        *ret = RwlockUnlock(rdi);
        return true;
    }
    if (nid == "BB+kb08Tl9A" || name == "scePthreadRwlockDestroy") {
        *ret = RwlockDestroy(rdi);
        return true;
    }

    return false;
}

} // namespace yotei::kernel
