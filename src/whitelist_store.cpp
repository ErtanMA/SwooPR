#include "whitelist_store.h"
#include "config.h"
#include <string.h>

#ifndef NATIVE_TEST
#include <Preferences.h>
#include <Arduino.h>
#endif

static char    s_macs[MAX_DEVICES][18];
static uint8_t s_count = 0;

#ifndef NATIVE_TEST
static void persist() {
    Preferences p;
    p.begin("wl", /*readOnly=*/false);
    p.putUChar("n", s_count);
    for (uint8_t i = 0; i < s_count; i++) {
        char key[4];
        snprintf(key, sizeof(key), "%u", (unsigned)i);
        p.putString(key, s_macs[i]);
    }
    p.end();
}
#endif

void whitelist_init() {
    s_count = 0;
    memset(s_macs, 0, sizeof(s_macs));
#ifndef NATIVE_TEST
    Preferences p;
    p.begin("wl", /*readOnly=*/true);
    uint8_t n = p.getUChar("n", 0);
    for (uint8_t i = 0; i < n && i < MAX_DEVICES; i++) {
        char key[4];
        snprintf(key, sizeof(key), "%u", (unsigned)i);
        String mac = p.getString(key, "");
        if (mac.length() > 0 && mac.length() <= 17) {
            strncpy(s_macs[s_count], mac.c_str(), 17);
            s_macs[s_count][17] = '\0';
            s_count++;
        }
    }
    p.end();
    Serial.printf("[WHITELIST] loaded %u entries\n", (unsigned)s_count);
#endif
}

bool whitelist_add(const char* mac) {
    if (whitelist_contains(mac)) return true;
    if (s_count >= MAX_DEVICES) return false;
    strncpy(s_macs[s_count], mac, 17);
    s_macs[s_count][17] = '\0';
    s_count++;
#ifndef NATIVE_TEST
    persist();
    Serial.printf("[WHITELIST] add %s\n", mac);
#endif
    return true;
}

bool whitelist_remove(const char* mac) {
    for (uint8_t i = 0; i < s_count; i++) {
        if (strncmp(s_macs[i], mac, 17) == 0) {
            for (uint8_t j = i; j < s_count - 1; j++)
                memcpy(s_macs[j], s_macs[j + 1], 18);
            memset(s_macs[s_count - 1], 0, 18);
            s_count--;
#ifndef NATIVE_TEST
            persist();
            Serial.printf("[WHITELIST] remove %s\n", mac);
#endif
            return true;
        }
    }
    return false;
}

bool whitelist_contains(const char* mac) {
    for (uint8_t i = 0; i < s_count; i++) {
        if (strncmp(s_macs[i], mac, 17) == 0) return true;
    }
    return false;
}
