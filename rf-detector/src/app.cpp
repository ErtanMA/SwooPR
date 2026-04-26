#include "app.h"
#include "scanner_wifi.h"
#include "scanner_ble.h"
#include "device_registry.h"
#include "threat_engine.h"
#include "whitelist_store.h"
#include "config.h"
#include "types.h"
#include <Arduino.h>

// Force first scan on boot by making the last-scan timestamps appear expired.
static uint32_t s_last_wifi_scan_ms = (uint32_t)(0UL - WIFI_SCAN_INTERVAL_MS);
static uint32_t s_last_ble_scan_ms  = (uint32_t)(0UL - BLE_SCAN_INTERVAL_MS);
static ScanResult s_scan_buf[MAX_DEVICES];

void app_init() {
    Serial.begin(115200);
    delay(100);
    whitelist_init();
    registry_init();
    wifi_scanner_init();
    ble_scanner_init();
    Serial.println("[APP] init complete");
}

void app_loop() {
    uint32_t now = millis();

    if (now - s_last_wifi_scan_ms >= WIFI_SCAN_INTERVAL_MS) {
        uint8_t n = wifi_scanner_scan(s_scan_buf, MAX_DEVICES);
        registry_update(s_scan_buf, n, millis());
        s_last_wifi_scan_ms = now;
    }

    now = millis();
    if (now - s_last_ble_scan_ms >= BLE_SCAN_INTERVAL_MS) {
        uint8_t n = ble_scanner_scan(s_scan_buf, MAX_DEVICES);
        registry_update(s_scan_buf, n, millis());
        s_last_ble_scan_ms = now;
    }

    now = millis();
    registry_drop_stale(now);

    uint8_t count;
    DetectedDevice* devices = registry_get_all(count);
    threat_score_all(devices, count);
    threat_sort(devices, count);
}
