// SPDX-FileCopyrightText: 2026 Kenta IDA <fuga@fugafuga.org>
// SPDX-License-Identifier: BSL-1.0

#include "board/board.hpp"

#include <optional>
#include <utility>

#include <M5Unified.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "board/io_expander_py32.hpp"
#include "board/si12t_touch.hpp"

namespace stackchan::board {

namespace {
constexpr const char* kTag = "board";
} // namespace

class Board::Impl {
public:
    Impl(Py32Expander&& expander, std::optional<Si12tTouch>&& touch) noexcept
        : expander_{std::move(expander)}, touch_{std::move(touch)}
    {
    }

    Py32Expander& expander() noexcept { return expander_; }
    Si12tTouch* touch() noexcept { return touch_ ? &*touch_ : nullptr; }

private:
    Py32Expander expander_;
    std::optional<Si12tTouch> touch_;
};

tl::expected<Board, Error> Board::begin()
{
    auto cfg = M5.config();
    M5.begin(cfg);
    M5.Display.setRotation(1);

    // PY32 can take up to ~1.2 s to come up after a cold reset. Match the
    // BSP's polling pattern: try once every 200 ms for ~1.2 s.
    tl::expected<Py32Expander, Error> expander = tl::unexpected{Error::ExpanderProbe};
    for (int attempt = 0; attempt < 6; ++attempt) {
        vTaskDelay(pdMS_TO_TICKS(200));
        expander = Py32Expander::probe();
        if (expander) {
            break;
        }
    }
    if (!expander) {
        ESP_LOGE(kTag, "PY32 IO expander probe failed at 0x%02X", Py32Expander::kAddress);
        return tl::unexpected{expander.error()};
    }

    if (auto r = expander->set_direction(Py32Expander::kPinServoPowerEnable, /*output=*/true); !r) {
        return tl::unexpected{r.error()};
    }
    if (auto r = expander->set_pull_up(Py32Expander::kPinServoPowerEnable, true); !r) {
        return tl::unexpected{r.error()};
    }
    if (auto r = expander->digital_write(Py32Expander::kPinServoPowerEnable, false); !r) {
        return tl::unexpected{r.error()};
    }

    // Top-mounted touch sensor (Si12T at 0x68). Optional — older bases
    // without the chip should still boot, so we just log a warning and
    // carry on if it doesn't respond.
    std::optional<Si12tTouch> touch;
    if (auto t = Si12tTouch::probe(); t) {
        touch.emplace(std::move(*t));
    } else {
        ESP_LOGW(kTag, "Si12T touch sensor not found at 0x%02X", Si12tTouch::kAddress);
    }

    Board board;
    board.impl_ = std::make_shared<Impl>(std::move(*expander), std::move(touch));
    ESP_LOGI(kTag, "board initialized (servo power: OFF)");
    return board;
}

M5GFX& Board::display() noexcept
{
    return M5.Display;
}

tl::expected<void, Error> Board::set_servo_power(bool on)
{
    return impl_->expander().digital_write(Py32Expander::kPinServoPowerEnable, on);
}

Si12tTouch* Board::touch_sensor() noexcept
{
    return impl_->touch();
}

} // namespace stackchan::board
