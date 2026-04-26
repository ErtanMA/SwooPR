#include "scanner_ble.h"
#include "config.h"
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <Arduino.h>
#include <string.h>

static BLEScan*    s_scan  = nullptr;
static ScanResult* s_out   = nullptr;
static uint8_t     s_max   = 0;
static uint8_t     s_count = 0;

class SwoopBLECallback : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice dev) override {
        if (s_count >= s_max || s_out == nullptr) return;
        ScanResult& r = s_out[s_count];

        r.protocol = DeviceProtocol::BLE;

        strncpy(r.mac, dev.getAddress().toString().c_str(), sizeof(r.mac) - 1);
        r.mac[sizeof(r.mac) - 1] = '\0';

        const char* name = dev.haveName() ? dev.getName().c_str() : "";
        strncpy(r.name_or_ssid, name, sizeof(r.name_or_ssid) - 1);
        r.name_or_ssid[sizeof(r.name_or_ssid) - 1] = '\0';

        r.channel = 0;
        r.rssi    = (int8_t)dev.getRSSI();

        Serial.printf("[BLE] %s  \"%s\"  %d dBm\n",
                      r.mac, r.name_or_ssid, (int)r.rssi);
        s_count++;
    }
};

static SwoopBLECallback s_callback;

void ble_scanner_init() {
    BLEDevice::init("");
    s_scan = BLEDevice::getScan();
    s_scan->setAdvertisedDeviceCallbacks(&s_callback, /*wantDuplicates=*/false);
    s_scan->setActiveScan(true);
    s_scan->setInterval(100);
    s_scan->setWindow(99);
    Serial.println("[BLE] init");
}

uint8_t ble_scanner_scan(ScanResult* out, uint8_t max_count) {
    s_out   = out;
    s_max   = max_count;
    s_count = 0;
    s_scan->start(BLE_SCAN_DURATION_MS / 1000, /*is_continue=*/false);
    s_scan->clearResults();
    s_out = nullptr;
    return s_count;
}
