#include "pad_hle.h"
#include <iostream>
#include <cstring>
#include <chrono>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <xinput.h>
#endif

namespace yotei::input {

namespace {

// PS5 ScePad digital button masks
constexpr uint32_t SCE_PAD_BUTTON_L3        = 0x00000002;
constexpr uint32_t SCE_PAD_BUTTON_R3        = 0x00000004;
constexpr uint32_t SCE_PAD_BUTTON_OPTIONS   = 0x00000008;
constexpr uint32_t SCE_PAD_BUTTON_UP        = 0x00000010;
constexpr uint32_t SCE_PAD_BUTTON_RIGHT     = 0x00000020;
constexpr uint32_t SCE_PAD_BUTTON_DOWN      = 0x00000040;
constexpr uint32_t SCE_PAD_BUTTON_LEFT      = 0x00000080;
constexpr uint32_t SCE_PAD_BUTTON_L2        = 0x00000100;
constexpr uint32_t SCE_PAD_BUTTON_R2        = 0x00000200;
constexpr uint32_t SCE_PAD_BUTTON_L1        = 0x00000400;
constexpr uint32_t SCE_PAD_BUTTON_R1        = 0x00000800;
constexpr uint32_t SCE_PAD_BUTTON_TRIANGLE  = 0x00001000;
constexpr uint32_t SCE_PAD_BUTTON_CIRCLE    = 0x00002000;
constexpr uint32_t SCE_PAD_BUTTON_CROSS     = 0x00004000;
constexpr uint32_t SCE_PAD_BUTTON_SQUARE    = 0x00008000;
constexpr uint32_t SCE_PAD_BUTTON_TOUCHPAD  = 0x00100000;

#ifdef _WIN32
typedef DWORD(WINAPI* PFN_XInputGetState)(DWORD dwUserIndex, XINPUT_STATE* pState);
typedef DWORD(WINAPI* PFN_XInputSetState)(DWORD dwUserIndex, XINPUT_VIBRATION* pVibration);

static PFN_XInputGetState pfn_XInputGetState = nullptr;
static PFN_XInputSetState pfn_XInputSetState = nullptr;
#endif

inline uint8_t NormalizeAxis(int16_t v) {
    // Map -32768..32767 to 0..255 (with 128 as neutral)
    int32_t shifted = static_cast<int32_t>(v) + 32768;
    int32_t scaled = (shifted * 255) / 65535;
    if (scaled < 0) scaled = 0;
    if (scaled > 255) scaled = 255;
    return static_cast<uint8_t>(scaled);
}

} // namespace

PadHleManager& PadHleManager::Instance() {
    static PadHleManager instance;
    return instance;
}

PadHleManager::PadHleManager() = default;
PadHleManager::~PadHleManager() {
    Shutdown();
}

bool PadHleManager::Initialize() {
#ifdef _WIN32
    if (!xinput_module_) {
        // Try xinput1_4.dll (Win 8/10/11) then fallback to xinput9_1_0.dll
        HMODULE mod = LoadLibraryW(L"xinput1_4.dll");
        if (!mod) {
            mod = LoadLibraryW(L"xinput9_1_0.dll");
        }
        if (mod) {
            xinput_module_ = mod;
            pfn_XInputGetState = reinterpret_cast<PFN_XInputGetState>(
                ::GetProcAddress(mod, "XInputGetState"));
            pfn_XInputSetState = reinterpret_cast<PFN_XInputSetState>(
                ::GetProcAddress(mod, "XInputSetState"));
            xinput_available_ = (pfn_XInputGetState != nullptr);
        }
    }

    std::cout << "[+] Initialized Pad HLE Manager: "
              << (xinput_available_ ? "XInput Backend Loaded (Host Gamepad Ready)" : "Virtual Gamepad Fallback")
              << "\n";
#endif
    return true;
}

void PadHleManager::Shutdown() {
#ifdef _WIN32
    if (xinput_module_) {
        FreeLibrary(reinterpret_cast<HMODULE>(xinput_module_));
        xinput_module_ = nullptr;
        pfn_XInputGetState = nullptr;
        pfn_XInputSetState = nullptr;
        xinput_available_ = false;
    }
#endif
}

bool PadHleManager::PollHostInput(ScePadData* out_data) {
    if (!out_data) return false;

    std::memset(out_data, 0, sizeof(ScePadData));

    // Neutral default analog sticks (128 = center)
    out_data->leftStickX = 128;
    out_data->leftStickY = 128;
    out_data->rightStickX = 128;
    out_data->rightStickY = 128;
    out_data->connected = 1;
    out_data->connectedCount = 1;

    // Neutral orientation quaternion: identity (x=0, y=0, z=0, w=1.0)
    out_data->orientation[0] = 0.0f;
    out_data->orientation[1] = 0.0f;
    out_data->orientation[2] = 0.0f;
    out_data->orientation[3] = 1.0f;

    auto now = std::chrono::steady_clock::now().time_since_epoch();
    out_data->timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now).count();

#ifdef _WIN32
    if (xinput_available_ && pfn_XInputGetState) {
        XINPUT_STATE state{};
        DWORD res = pfn_XInputGetState(0, &state);
        if (res == ERROR_SUCCESS) {
            xinput_connected_ = true;
            uint32_t buttons = 0;
            const auto& pad = state.Gamepad;

            if (pad.wButtons & XINPUT_GAMEPAD_DPAD_UP)        buttons |= SCE_PAD_BUTTON_UP;
            if (pad.wButtons & XINPUT_GAMEPAD_DPAD_DOWN)      buttons |= SCE_PAD_BUTTON_DOWN;
            if (pad.wButtons & XINPUT_GAMEPAD_DPAD_LEFT)      buttons |= SCE_PAD_BUTTON_LEFT;
            if (pad.wButtons & XINPUT_GAMEPAD_DPAD_RIGHT)     buttons |= SCE_PAD_BUTTON_RIGHT;
            if (pad.wButtons & XINPUT_GAMEPAD_START)          buttons |= SCE_PAD_BUTTON_OPTIONS;
            if (pad.wButtons & XINPUT_GAMEPAD_LEFT_THUMB)     buttons |= SCE_PAD_BUTTON_L3;
            if (pad.wButtons & XINPUT_GAMEPAD_RIGHT_THUMB)    buttons |= SCE_PAD_BUTTON_R3;
            if (pad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER)  buttons |= SCE_PAD_BUTTON_L1;
            if (pad.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER) buttons |= SCE_PAD_BUTTON_R1;
            if (pad.wButtons & XINPUT_GAMEPAD_A)              buttons |= SCE_PAD_BUTTON_CROSS;
            if (pad.wButtons & XINPUT_GAMEPAD_B)              buttons |= SCE_PAD_BUTTON_CIRCLE;
            if (pad.wButtons & XINPUT_GAMEPAD_X)              buttons |= SCE_PAD_BUTTON_SQUARE;
            if (pad.wButtons & XINPUT_GAMEPAD_Y)              buttons |= SCE_PAD_BUTTON_TRIANGLE;

            if (pad.bLeftTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD)  buttons |= SCE_PAD_BUTTON_L2;
            if (pad.bRightTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD) buttons |= SCE_PAD_BUTTON_R2;

            out_data->buttons = buttons;
            out_data->leftStickX  = NormalizeAxis(pad.sThumbLX);
            out_data->leftStickY  = NormalizeAxis(-pad.sThumbLY); // invert Y for PS standard
            out_data->rightStickX = NormalizeAxis(pad.sThumbRX);
            out_data->rightStickY = NormalizeAxis(-pad.sThumbRY);

            out_data->analogButtons[0] = pad.bLeftTrigger;
            out_data->analogButtons[1] = pad.bRightTrigger;
            return true;
        } else {
            xinput_connected_ = false;
        }
    }
#endif
    return true;
}

int32_t PadHleManager::Init() {
    return 0; // SCE_OK
}

int32_t PadHleManager::Open(int32_t userId, int32_t type, int32_t index, const void* pParam) {
    (void)userId; (void)type; (void)index; (void)pParam;
    return primary_handle_;
}

int32_t PadHleManager::Close(int32_t handle) {
    (void)handle;
    return 0; // SCE_OK
}

int32_t PadHleManager::ReadState(int32_t handle, ScePadData* pData) {
    if (!pData) return 0x8002000E; // SCE_KERNEL_ERROR_EFAULT
    std::lock_guard<std::mutex> lock(pad_lock_);
    PollHostInput(pData);
    return 0; // SCE_OK
}

int32_t PadHleManager::Read(int32_t handle, ScePadData* pData, int32_t num) {
    if (!pData || num <= 0) return 0x8002000E;
    std::lock_guard<std::mutex> lock(pad_lock_);
    PollHostInput(pData);
    return 1; // returned 1 packet
}

int32_t PadHleManager::SetLightBar(int32_t handle, const ScePadColor* pColor) {
    return 0; // SCE_OK
}

int32_t PadHleManager::SetVibration(int32_t handle, const ScePadVibrationParam* pParam) {
#ifdef _WIN32
    if (xinput_available_ && pfn_XInputSetState && pParam) {
        XINPUT_VIBRATION vib{};
        vib.wLeftMotorSpeed = static_cast<WORD>(pParam->largeMotor) * 257;
        vib.wRightMotorSpeed = static_cast<WORD>(pParam->smallMotor) * 257;
        pfn_XInputSetState(0, &vib);
    }
#endif
    return 0;
}

int32_t PadHleManager::ResetOrientation(int32_t handle) {
    return 0;
}

int32_t PadHleManager::ResetLightBar(int32_t handle) {
    return 0;
}

int32_t PadHleManager::SetTriggerEffect(int32_t handle, const void* pParam) {
    return 0;
}

int32_t PadHleManager::GetDataPortInfo(int32_t handle, void* pInfo) {
    if (pInfo) {
        std::memset(pInfo, 0, 32);
    }
    return 0;
}

int32_t PadHleManager::GetSensorInfo(int32_t handle, void* pInfo) {
    if (pInfo) {
        std::memset(pInfo, 0, 64);
    }
    return 0;
}

int32_t PadHleManager::GetHandle(int32_t userId, int32_t type, int32_t index) {
    return primary_handle_;
}

int32_t PadHleManager::SetMotionSensorState(int32_t handle, bool bEnable) {
    return 0;
}

bool PadHleManager::DispatchNid(const std::string& nid, const std::string& name,
                                uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx,
                                uint64_t r8, uint64_t r9, uint64_t* ret) {
    if (name == "scePadInit") {
        *ret = Init();
        return true;
    }
    if (name == "scePadOpen") {
        *ret = Open(static_cast<int32_t>(rdi), static_cast<int32_t>(rsi),
                    static_cast<int32_t>(rdx), reinterpret_cast<const void*>(rcx));
        return true;
    }
    if (name == "scePadClose") {
        *ret = Close(static_cast<int32_t>(rdi));
        return true;
    }
    if (name == "scePadReadState") {
        *ret = ReadState(static_cast<int32_t>(rdi), reinterpret_cast<ScePadData*>(rsi));
        return true;
    }
    if (name == "scePadRead") {
        *ret = Read(static_cast<int32_t>(rdi), reinterpret_cast<ScePadData*>(rsi),
                    static_cast<int32_t>(rdx));
        return true;
    }
    if (name == "scePadSetLightBar") {
        *ret = SetLightBar(static_cast<int32_t>(rdi), reinterpret_cast<const ScePadColor*>(rsi));
        return true;
    }
    if (name == "scePadSetVibration") {
        *ret = SetVibration(static_cast<int32_t>(rdi), reinterpret_cast<const ScePadVibrationParam*>(rsi));
        return true;
    }
    if (name == "scePadResetOrientation") {
        *ret = ResetOrientation(static_cast<int32_t>(rdi));
        return true;
    }
    if (name == "scePadResetLightBar") {
        *ret = ResetLightBar(static_cast<int32_t>(rdi));
        return true;
    }
    if (name == "scePadSetTriggerEffect") {
        *ret = SetTriggerEffect(static_cast<int32_t>(rdi), reinterpret_cast<const void*>(rsi));
        return true;
    }
    if (name == "scePadGetDataPortInfo") {
        *ret = GetDataPortInfo(static_cast<int32_t>(rdi), reinterpret_cast<void*>(rsi));
        return true;
    }
    if (name == "scePadGetSensorInfo") {
        *ret = GetSensorInfo(static_cast<int32_t>(rdi), reinterpret_cast<void*>(rsi));
        return true;
    }
    if (name == "scePadGetHandle") {
        *ret = GetHandle(static_cast<int32_t>(rdi), static_cast<int32_t>(rsi), static_cast<int32_t>(rdx));
        return true;
    }
    if (name == "scePadSetMotionSensorState") {
        *ret = SetMotionSensorState(static_cast<int32_t>(rdi), rsi != 0);
        return true;
    }
    return false;
}

} // namespace yotei::input
