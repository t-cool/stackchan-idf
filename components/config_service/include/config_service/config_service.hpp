// SPDX-FileCopyrightText: 2026 Kenta IDA <fuga@fugafuga.org>
// SPDX-License-Identifier: BSL-1.0

#pragma once

#include <cstdint>
#include <string>
#include <tl/expected.hpp>

namespace stackchan::config {

// Realtime conversation backend. Selects which provider's WebSocket the
// conversation task talks to, and which API key it picks up at boot.
enum class Provider : std::uint8_t {
    OpenAi = 0,   // OpenAI Realtime API (wss://api.openai.com/v1/realtime)
    Gemini = 1,   // Google Gemini Live API (wss://generativelanguage.googleapis.com/...)
};

struct DeviceConfig {
    std::string wifi_ssid;
    std::string wifi_password;
    std::string openai_api_key;
    std::string gemini_api_key;
    Provider provider = Provider::OpenAi;
    // Master switch for the OpenAI Realtime conversation task. Independent
    // of openai_api_key so the key can stay persisted while the feature is
    // turned off (saves data, lets the user take Stack-chan offline without
    // losing setup). Defaults to true for backwards compatibility with
    // existing NVS contents that pre-date this flag.
    bool openai_enabled = true;
    // JSON document carrying the user-tunable jtts babble parameters and
    // phrase list. The producer (BLE client) writes the raw JSON; the
    // consumer (main/speech.cpp) parses on startup. Empty → compile-time
    // defaults. Capped at ~768 bytes plain text on the wire.
    std::string jtts_config_json;
};

enum class Error {
    NvsInit,
    NvsWrite,
    NimbleInit,
    GapAdvStart,
    GattRegister,
    // Application-layer crypto session (X25519 + AES-256-GCM).
    CryptoNotReady, // operation attempted before key exchange completed
    CryptoBadKey,   // peer pubkey rejected / ECDH failed
    CryptoAuth,     // AES-GCM authentication tag mismatch
    CryptoRng,      // ctr_drbg seeding / random failure
};

// Read device config from NVS namespace "stackchan_cfg". Missing keys → empty string.
DeviceConfig load();

// Start NimBLE host + GATT server + advertising. Non-fatal on failure: caller logs and continues.
tl::expected<void, Error> start(const DeviceConfig& current);

// Update Wi-Fi connectivity status; sends Status NOTIFY if a client is subscribed.
// Thread-safe — may be called from any task.
void notify_wifi_connected(bool connected);

} // namespace stackchan::config
