#include "device_registry.h"
#include <Arduino.h>
#include <string.h>

static DetectedDevice s_devices[MAX_DEVICES];
static uint8_t        s_count = 0;

void registry_init() {
    s_count = 0;
    memset(s_devices, 0, sizeof(s_devices));
    Serial.println("[REGISTRY] init");
}

static int find_device(const char* mac, DeviceProtocol proto) {
    for (uint8_t i = 0; i < s_count; i++) {
        if (s_devices[i].protocol == proto &&
            strncmp(s_devices[i].mac, mac, 17) == 0) {
            return (int)i;
        }
    }
    return -1;
}

void registry_update(const ScanResult* results, uint8_t count, uint32_t now_ms) {
    for (uint8_t i = 0; i < count; i++) {
        const ScanResult& r = results[i];
        int idx = find_device(r.mac, r.protocol);

        if (idx >= 0) {
            DetectedDevice& d = s_devices[idx];
            d.smoothed_rssi = (int8_t)(
                (1.0f - RSSI_SMOOTH_ALPHA) * (float)d.smoothed_rssi +
                RSSI_SMOOTH_ALPHA           * (float)r.rssi);
            d.rssi         = r.rssi;
            d.channel      = r.channel;
            d.last_seen_ms = now_ms;
            if (d.times_seen < 0xFFFFU) d.times_seen++;
            strncpy(d.name_or_ssid, r.name_or_ssid, sizeof(d.name_or_ssid) - 1);
            Serial.printf("[REGISTRY] merge %s  smoothed=%d dBm\n",
                          d.mac, (int)d.smoothed_rssi);
        } else if (s_count < MAX_DEVICES) {
            DetectedDevice& d = s_devices[s_count];
            memset(&d, 0, sizeof(d));
            d.protocol     = r.protocol;
            strncpy(d.mac, r.mac, sizeof(d.mac) - 1);
            strncpy(d.name_or_ssid, r.name_or_ssid, sizeof(d.name_or_ssid) - 1);
            d.channel       = r.channel;
            d.rssi          = r.rssi;
            d.smoothed_rssi = r.rssi;
            d.first_seen_ms = now_ms;
            d.last_seen_ms  = now_ms;
            d.times_seen    = 1;
            s_count++;
            Serial.printf("[REGISTRY] add %s  %d dBm\n", d.mac, (int)d.rssi);
        }
    }
}

void registry_drop_stale(uint32_t now_ms) {
    uint8_t i = 0;
    while (i < s_count) {
        if ((now_ms - s_devices[i].last_seen_ms) >= STALE_TIMEOUT_MS) {
            Serial.printf("[REGISTRY] drop_stale %s\n", s_devices[i].mac);
            s_devices[i] = s_devices[--s_count];
        } else {
            i++;
        }
    }
}

DetectedDevice* registry_get_all(uint8_t& out_count) {
    out_count = s_count;
    return s_devices;
}

void registry_set_whitelisted(const char* mac, DeviceProtocol proto, bool state) {
    int idx = find_device(mac, proto);
    if (idx >= 0) {
        s_devices[idx].whitelisted = state;
        Serial.printf("[REGISTRY] whitelist %s -> %s\n", mac, state ? "true" : "false");
    }
}
