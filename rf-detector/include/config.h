#pragma once
#include <cstdint>

// Registry
constexpr uint8_t  MAX_DEVICES          = 32;
constexpr uint32_t STALE_TIMEOUT_MS     = 30000; // ms before unseen device is dropped
constexpr float    RSSI_SMOOTH_ALPHA    = 0.3f;  // EMA weight for new RSSI sample

// Scan intervals
constexpr uint32_t WIFI_SCAN_INTERVAL_MS = 5000;
constexpr uint32_t BLE_SCAN_DURATION_MS  = 3000; // BLE active scan window
constexpr uint32_t BLE_SCAN_INTERVAL_MS  = 5000;

// Threat scoring — all values in dBm or raw score points
constexpr int8_t  RSSI_STRONG_THRESHOLD  = -60;
constexpr int8_t  RSSI_MEDIUM_THRESHOLD  = -80;
constexpr uint8_t THREAT_SCORE_MAX       = 100;
constexpr uint8_t THREAT_SCORE_STRONG    = 40;
constexpr uint8_t THREAT_SCORE_MEDIUM    = 20;
constexpr uint8_t THREAT_SCORE_SEEN_MULT = 1;   // points per times_seen, up to THREAT_SEEN_CAP
constexpr uint8_t THREAT_SEEN_CAP        = 20;
constexpr uint8_t THREAT_SCORE_HIDDEN    = 30;  // bonus for devices with no SSID/name
constexpr uint8_t THREAT_SCORE_CAMERA_OUI = 40; // MAC prefix matched a known camera manufacturer

// Guard mode
constexpr int8_t   GUARD_STRONGER_DELTA  = 10;    // dBm increase that triggers STRONGER_SIGNAL
constexpr uint32_t GUARD_BASELINE_MS     = 10000; // settle time before guard activates

// Direction tracker
constexpr uint8_t DIRECTION_HISTORY_LEN  = 16;   // rolling RSSI window for peak tracking

// Display
constexpr uint8_t  DISPLAY_MAX_ROWS      = 6;    // usable rows on 128×64 OLED at default font
constexpr uint32_t DISPLAY_REFRESH_MS    = 250;

// Buzzer
constexpr uint16_t BUZZ_FREQ_ALERT       = 2000; // Hz
constexpr uint16_t BUZZ_FREQ_CONFIRM     = 1000; // Hz
constexpr uint32_t BUZZ_DURATION_SHORT   = 100;  // ms
constexpr uint32_t BUZZ_DURATION_LONG    = 400;  // ms
