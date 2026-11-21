#include "graphics/frame_loop.h"
#include "graphics/hiz_readback.h"
#include "graphics/video_out_hle.h"
#include "graphics/vk_backend.h"
#include "audio/audio_out_hle.h"
#include "hle/nid_registry.h"
#include "input/pad_hle.h"
#include "kernel/threads.h"
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace yotei::graphics {

FrameLoopEngine& FrameLoopEngine::Instance() {
    static FrameLoopEngine instance;
    return instance;
}

bool FrameLoopEngine::Initialize(int32_t audio_ctx_id, int32_t video_handle) {
    audio_ctx_id_ = audio_ctx_id;
    video_handle_ = video_handle;
    current_frame_ = 0;
    summary_ = {};
    initialized_ = true;
    return true;
}

void FrameLoopEngine::Shutdown() {
    initialized_ = false;
}

FrameTelemetry FrameLoopEngine::ExecuteFrameTick(
    uint32_t total_submeshes,
    uint32_t indices_per_draw,
    const std::vector<uint32_t>& compute_spirv) {

    auto t_start = std::chrono::high_resolution_clock::now();
    FrameTelemetry telemetry{};
    telemetry.frame_index = current_frame_++;

    // 1. Poll Win32 Window Messages & Read XInput / DualSense Gamepad State
    auto& video_out = VideoOutHleManager::Instance();
    video_out.PollEvents();

    yotei::input::ScePadData pad_data{};
    yotei::input::PadHleManager::Instance().ReadState(1, &pad_data);
    telemetry.pad_buttons_mask = pad_data.buttons;

    // 2. Feed Low-Latency Audio Grain (256 stereo float frames @ 48 kHz) into WASAPI / AudioOut2
    auto& audio = yotei::audio::AudioOut2HleManager::Instance();
    if (audio.IsInitialized() && audio_ctx_id_ > 0) {
        constexpr uint32_t kGrainFrames = 256;
        float grain_pcm[kGrainFrames * 2]{};
        float phase_base = static_cast<float>(telemetry.frame_index * kGrainFrames);
        for (uint32_t i = 0; i < kGrainFrames; ++i) {
            float s = 0.08f * std::sin(2.0f * 3.14159265f * 220.0f * (phase_base + i) / 48000.0f);
            grain_pcm[i * 2 + 0] = s;
            grain_pcm[i * 2 + 1] = s;
        }
        if (audio.ContextPush(audio_ctx_id_, grain_pcm, kGrainFrames, telemetry.frame_index + 100) == 0) {
            telemetry.audio_frames_pushed = kGrainFrames;
        }
    }

    // 3. Hi-Z Conservative Reverse-Z Occlusion Culling Pass across Submeshes
    auto& hiz = HizReadbackEngine::Instance();
    auto& vk = VulkanHostBackend::Instance();

    telemetry.submeshes_tested = total_submeshes;
    for (uint32_t sm = 0; sm < total_submeshes; ++sm) {
        // Distribute submeshes across screen space and depth
        float angle = static_cast<float>(sm) * 0.35f + static_cast<float>(telemetry.frame_index) * 0.05f;
        float cx = 0.5f * std::cos(angle);
        float cy = 0.4f * std::sin(angle);
        // Every 3rd submesh is placed behind the central occluder (z in [0.15..0.35]), others in foreground (z in [0.88..0.95])
        bool behind_wall = ((sm % 3) == 1);
        HizBoundingBox bbox{};
        bbox.min_x = behind_wall ? -0.15f : (cx - 0.08f);
        bbox.max_x = behind_wall ?  0.15f : (cx + 0.08f);
        bbox.min_y = behind_wall ? -0.15f : (cy - 0.08f);
        bbox.max_y = behind_wall ?  0.15f : (cy + 0.08f);
        bbox.min_z = behind_wall ?  0.15f : 0.88f;
        bbox.max_z = behind_wall ?  0.30f : 0.94f;

        bool occluded = hiz.IsInitialized() ? hiz.QueryOcclusion(bbox, true) : false;
        if (occluded) {
            ++telemetry.submeshes_culled;
        } else {
            ++telemetry.submeshes_drawn;
        }
    }

    // 4. PM4 Compute Simulation Pass (e.g., CS Cloth / Wind Physics)
    // Note: Multi-Stage 3D Hardware Draw is executed directly into the Swapchain Framebuffer inside SubmitFlip()
    if (!compute_spirv.empty() && vk.IsInitialized()) {
        if (vk.ExecuteCompute(compute_spirv, 16, 1, 1)) {
            ++telemetry.compute_dispatches;
        }
    }
    (void)indices_per_draw;

    // 5. Triple-Buffered Swapchain Flip (0, 1, 2 ring) with Vulkan Present Transition
    int32_t triple_buf_idx = static_cast<int32_t>(telemetry.frame_index % 3);
    telemetry.present_ok = video_out.SubmitFlip(
        video_handle_,
        triple_buf_idx,
        0,
        static_cast<int64_t>(telemetry.frame_index));

    auto t_end = std::chrono::high_resolution_clock::now();
    telemetry.frame_time_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    // 6. Update Dynamic Win32 Window Title with Live Telemetry HUD
    double inst_fps = (telemetry.frame_time_ms > 0.0) ? (1000.0 / telemetry.frame_time_ms) : 0.0;
    std::ostringstream hud;
    hud << "Ghost of Yotei (PPSA26344) | Frame #" << (telemetry.frame_index + 1)
        << " | " << std::fixed << std::setprecision(2) << telemetry.frame_time_ms << " ms ("
        << std::setprecision(0) << inst_fps << " FPS)"
        << " | Hi-Z: Drawn=" << telemetry.submeshes_drawn << " Culled=" << telemetry.submeshes_culled
        << " | Workers=" << yotei::kernel::ThreadManager::Instance().GetActiveThreadCount()
        << " | HLE Calls=" << yotei::hle::NidRegistry::GetTotalDispatchedCalls();
    video_out.UpdateWindowTelemetryTitle(hud.str());

    return telemetry;
}

FrameLoopSummary FrameLoopEngine::RunFrameLoop(
    uint32_t num_frames,
    uint32_t total_submeshes,
    uint32_t indices_per_draw,
    const std::vector<uint32_t>& compute_spirv) {

    summary_ = {};
    for (uint32_t f = 0; f < num_frames; ++f) {
        auto ft = ExecuteFrameTick(total_submeshes, indices_per_draw, compute_spirv);
        summary_.total_frames_executed++;
        summary_.total_elapsed_ms += ft.frame_time_ms;
        summary_.total_submeshes_drawn += ft.submeshes_drawn;
        summary_.total_submeshes_culled += ft.submeshes_culled;
        summary_.total_compute_dispatches += ft.compute_dispatches;
        summary_.total_audio_frames += ft.audio_frames_pushed;
        if (ft.present_ok) {
            summary_.total_flips_presented++;
        }
    }

    if (summary_.total_frames_executed > 0) {
        summary_.avg_frame_time_ms = summary_.total_elapsed_ms / summary_.total_frames_executed;
        summary_.effective_fps = (summary_.avg_frame_time_ms > 0.0)
            ? (1000.0 / summary_.avg_frame_time_ms)
            : 0.0;
    }
    return summary_;
}

} // namespace yotei::graphics
