#pragma once

#include <cstdint>
#include <mutex>
#include <string>

namespace yotei::input {

#pragma pack(push, 1)
struct ScePadData {
    uint32_t buttons;           // 0x00: Digital button bitmask
    uint8_t  leftStickX;        // 0x04: 0..255 (128 = center)
    uint8_t  leftStickY;        // 0x05: 0..255 (128 = center)
    uint8_t  rightStickX;       // 0x06: 0..255 (128 = center)
    uint8_t  rightStickY;       // 0x07: 0..255 (128 = center)
    uint8_t  analogButtons[8];  // 0x08: [0]=L2 trigger, [1]=R2 trigger, etc.
    float    orientation[4];    // 0x10: Quaternion (x, y, z, w)
    float    acceleration[3];   // 0x20: Accelerometer (x, y, z)
    float    angularVelocity[3];// 0x2C: Gyroscope (x, y, z)
    uint8_t  touchNumber;       // 0x38: Number of active touch points
    uint8_t  padding[3];        // 0x39
    uint8_t  touchData[16];     // 0x3C: Touch point 0 & 1 structures
    uint32_t reserved[4];       // 0x4C
    uint8_t  connected;         // 0x5C: 1 if connected, 0 otherwise
    uint8_t  padding2[3];       // 0x5D
    uint64_t timestamp;         // 0x60: Microseconds timestamp
    uint32_t connectedCount;    // 0x68
    uint8_t  deviceUniqueDataLen;
    uint8_t  deviceUniqueData[15];
};
#pragma pack(pop)

struct ScePadVibrationParam {
    uint8_t largeMotor;
    uint8_t smallMotor;
};

struct ScePadColor {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t reserved;
};

class PadHleManager {
public:
    static PadHleManager& Instance();

    bool Initialize();
    void Shutdown();

    // HLE functions matching PS5 libScePad ABI
    int32_t Init();
    int32_t Open(int32_t userId, int32_t type, int32_t index, const void* pParam);
    int32_t Close(int32_t handle);
    int32_t ReadState(int32_t handle, ScePadData* pData);
    int32_t Read(int32_t handle, ScePadData* pData, int32_t num);
    int32_t SetLightBar(int32_t handle, const ScePadColor* pColor);
    int32_t SetVibration(int32_t handle, const ScePadVibrationParam* pParam);
    int32_t ResetOrientation(int32_t handle);
    int32_t ResetLightBar(int32_t handle);
    int32_t SetTriggerEffect(int32_t handle, const void* pParam);
    int32_t GetDataPortInfo(int32_t handle, void* pInfo);
    int32_t GetSensorInfo(int32_t handle, void* pInfo);
    int32_t GetHandle(int32_t userId, int32_t type, int32_t index);
    int32_t SetMotionSensorState(int32_t handle, bool bEnable);

    // Dispatcher for NID routing
    bool DispatchNid(const std::string& nid, const std::string& name,
                     uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx,
                     uint64_t r8, uint64_t r9, uint64_t* ret);

    bool IsGamepadConnected() const { return xinput_connected_; }

private:
    PadHleManager();
    ~PadHleManager();

    bool PollHostInput(ScePadData* out_data);

    void* xinput_module_ = nullptr;
    bool xinput_available_ = false;
    bool xinput_connected_ = false;
    uint32_t active_user_id_ = 0x10000001;
    int32_t primary_handle_ = 1;
    mutable std::mutex pad_lock_;
};

} // namespace yotei::input
