#pragma once
#include <cstdint>

enum class DeviceProtocol : uint8_t { WIFI, BLE };

enum class AppMode : uint8_t { SURVEY, DIRECTION, WHITELIST, GUARD };

enum class AlertState : uint8_t { NONE, NEW_DEVICE, STRONGER_SIGNAL, RETURNED };

struct DetectedDevice {
    DeviceProtocol protocol;
    char           mac[18];
    char           name_or_ssid[33];
    uint8_t        channel;
    int8_t         rssi;
    int8_t         smoothed_rssi;
    uint32_t       first_seen_ms;
    uint32_t       last_seen_ms;
    uint16_t       times_seen;
    bool           whitelisted;
    bool           random_mac;   // locally administered bit set — likely a rotating privacy MAC
    bool           camera_oui;   // MAC prefix matched a known surveillance manufacturer
    uint8_t        threat_score;
};

struct ScanResult {
    DeviceProtocol protocol;
    char           mac[18];
    char           name_or_ssid[33];
    uint8_t        channel;
    int8_t         rssi;
};
