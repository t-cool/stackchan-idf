// SPDX-FileCopyrightText: 2026 Kenta IDA <fuga@fugafuga.org>
// SPDX-License-Identifier: BSL-1.0

#pragma once

#include <array>
#include <cstdint>
#include <tl/expected.hpp>

#include "board/board.hpp"

namespace stackchan::board {

// Si12T capacitive touch IC (I²C 0x68 on the internal bus) wired to the
// three top zones on the Stack-chan base — index 0 = Front, 1 = Middle,
// 2 = Back. Each zone reports a 2-bit intensity (0 = idle, 1–3 = increasing
// touch). The chip is shared with PMIC / IO expander / LCD touch on the
// internal I²C bus, so we go through M5Unified's m5::In_I2C wrapper.
class Si12tTouch {
public:
    static constexpr std::uint8_t kAddress = 0x68;
    static constexpr std::uint32_t kI2cFreq = 100'000;
    static constexpr std::size_t kZoneCount = 3;

    enum class Zone : std::size_t { Front = 0, Middle = 1, Back = 2 };

    struct Reading {
        std::array<std::uint8_t, kZoneCount> intensities{};

        bool any_touched() const noexcept
        {
            return intensities[0] > 0 || intensities[1] > 0 || intensities[2] > 0;
        }
        std::uint8_t front() const noexcept { return intensities[0]; }
        std::uint8_t middle() const noexcept { return intensities[1]; }
        std::uint8_t back() const noexcept { return intensities[2]; }
    };

    static tl::expected<Si12tTouch, Error> probe(std::uint8_t address = kAddress);

    // Single I²C read of the OUTPUT1 register, parsed into per-zone
    // intensities. Returns an all-zero Reading on bus error.
    Reading read();

    std::uint8_t address() const noexcept { return address_; }

private:
    explicit Si12tTouch(std::uint8_t address) noexcept : address_{address} {}

    bool write_register(std::uint8_t reg, std::uint8_t value);

    std::uint8_t address_;
};

} // namespace stackchan::board
