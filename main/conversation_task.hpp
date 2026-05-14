// SPDX-FileCopyrightText: 2026 Kenta IDA <fuga@fugafuga.org>
// SPDX-License-Identifier: BSL-1.0

#pragma once

#include "board/si12t_touch.hpp"
#include "shared_state.hpp"

namespace stackchan::app {

struct ConversationTaskArgs {
    SharedState* state;
    const char* api_key;          // OpenAI API key; empty disables the conversation
    board::Si12tTouch* touch;     // top touch sensor for barge-in; may be null
};

// Pinned to core 0. Owns the OpenAI Realtime client and drives the half-duplex
// mic/speaker I2S state machine, avatar mouth sync, balloon text, and tool
// dispatch. Waits for Wi-Fi before connecting.
void start_conversation_task(ConversationTaskArgs& args);

} // namespace stackchan::app
