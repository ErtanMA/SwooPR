#include "scanner_wifi.h"
#include "config.h"
#include <WiFi.h>
#include <Arduino.h>
#include <string.h>

void wifi_scanner_init() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    Serial.println("[WIFI] init");
}

uint8_t wifi_scanner_scan(ScanResult* out, uint8_t max_count) {
    int found = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true);
    if (found <= 0) {
        Serial.printf("[WIFI] scan returned %d\n", found);
        return 0;
    }
    uint8_t written = 0;
    for (int i = 0; i < found && written < max_count; i++) {
        ScanResult& r = out[written];
        r.protocol = DeviceProtocol::WIFI;

        String bssid = WiFi.BSSIDstr(i);
        strncpy(r.mac, bssid.c_str(), sizeof(r.mac) - 1);
        r.mac[sizeof(r.mac) - 1] = '\0';

        String ssid = WiFi.SSID(i);
        strncpy(r.name_or_ssid, ssid.c_str(), sizeof(r.name_or_ssid) - 1);
        r.name_or_ssid[sizeof(r.name_or_ssid) - 1] = '\0';

        r.channel = (uint8_t)WiFi.channel(i);
        r.rssi    = (int8_t)WiFi.RSSI(i);

        Serial.printf("[WIFI] %s  \"%s\"  ch%u  %d dBm\n",
                      r.mac, r.name_or_ssid, r.channel, (int)r.rssi);
        written++;
    }
    WiFi.scanDelete();
    return written;
}
