#include "threat_engine.h"
#include "config.h"
#include <Arduino.h>

static uint8_t score_device(const DetectedDevice& d) {
    if (d.whitelisted) return 0;

    uint8_t score = 0;

    if (d.smoothed_rssi > RSSI_STRONG_THRESHOLD)
        score += THREAT_SCORE_STRONG;
    else if (d.smoothed_rssi > RSSI_MEDIUM_THRESHOLD)
        score += THREAT_SCORE_MEDIUM;

    // Random MACs rotate per-device, so times_seen counts different physical
    // devices as one — don't reward persistence for them.
    if (!d.random_mac) {
        uint8_t seen = (d.times_seen < THREAT_SEEN_CAP)
                       ? (uint8_t)d.times_seen
                       : THREAT_SEEN_CAP;
        score += seen * THREAT_SCORE_SEEN_MULT;
    }

    if (d.name_or_ssid[0] == '\0')
        score += THREAT_SCORE_HIDDEN;

    if (d.camera_oui)
        score += THREAT_SCORE_CAMERA_OUI;

    return (score > THREAT_SCORE_MAX) ? THREAT_SCORE_MAX : score;
}

void threat_score_all(DetectedDevice* devices, uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        devices[i].threat_score = score_device(devices[i]);
        Serial.printf("[THREAT] %s  score=%u\n",
                      devices[i].mac, (unsigned)devices[i].threat_score);
    }
}

void threat_sort(DetectedDevice* devices, uint8_t count) {
    // Insertion sort — count is bounded by MAX_DEVICES (32), so O(n²) is fine.
    for (uint8_t i = 1; i < count; i++) {
        DetectedDevice key = devices[i];
        int8_t j = (int8_t)i - 1;
        while (j >= 0 && devices[j].threat_score < key.threat_score) {
            devices[j + 1] = devices[j];
            j--;
        }
        devices[(uint8_t)(j + 1)] = key;
    }
}
