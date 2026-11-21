#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace yotei::graphics {

struct FrameTelemetry {
    uint64_t frame_index = 0;
    double   frame_time_ms = 0.0;
    uint32_t submeshes_tested = 0;
    uint32_t submeshes_drawn = 0;
    uint32_t submeshes_culled = 0;
    uint32_t compute_dispatches = 0;
    uint32_t audio_frames_pushed = 0;
    uint32_t pad_buttons_mask = 0;
    bool     present_ok = false;
};

struct FrameLoopSummary {
    uint32_t total_frames_executed = 0;
    double   total_elapsed_ms = 0.0;
    double   avg_frame_time_ms = 0.0;
    double   effective_fps = 0.0;
    uint64_t total_submeshes_drawn = 0;
    uint64_t total_submeshes_culled = 0;
    uint64_t total_compute_dispatches = 0;
    uint64_t total_audio_frames = 0;
    uint64_t total_flips_presented = 0;
};

class FrameLoopEngine {
public:
    static FrameLoopEngine& Instance();

    bool Initialize(int32_t audio_ctx_id = 1, int32_t video_handle = 1);
    void Shutdown();

    // Execute a single integrated frame tick (Input -> Audio -> Hi-Z Culling -> PM4 Compute/Draw -> Present Flip)
    FrameTelemetry ExecuteFrameTick(
        uint32_t total_submeshes,
        uint32_t indices_per_draw,
        const std::vector<uint32_t>& compute_spirv);

    // Run N frames of the integrated game loop and return aggregated telemetry
    FrameLoopSummary RunFrameLoop(
        uint32_t num_frames,
        uint32_t total_submeshes,
        uint32_t indices_per_draw,
        const std::vector<uint32_t>& compute_spirv);

    const FrameLoopSummary& GetLastSummary() const { return summary_; }

private:
    FrameLoopEngine() = default;

    bool initialized_ = false;
    int32_t audio_ctx_id_ = 1;
    int32_t video_handle_ = 1;
    uint64_t current_frame_ = 0;
    FrameLoopSummary summary_{};
};

} // namespace yotei::graphics
