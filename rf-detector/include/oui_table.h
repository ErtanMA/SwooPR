#pragma once
#include <cstdint>
#include <cstring>
#include <cstdio>

// OUI prefixes for known surveillance camera and IoT manufacturers.
// First 3 bytes of the MAC identify the hardware vendor (IEEE assigned).
// Verify and extend at: https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries

struct OuiEntry {
    uint8_t     prefix[3];
    const char* vendor;
};

static const OuiEntry OUI_CAMERA_TABLE[] = {
    // Hikvision
    { {0x44, 0x19, 0xB6}, "Hikvision" },
    { {0xBC, 0xAD, 0x28}, "Hikvision" },
    { {0x4C, 0x11, 0xBF}, "Hikvision" },
    { {0xC0, 0x56, 0xE3}, "Hikvision" },
    { {0x10, 0x12, 0xFB}, "Hikvision" },
    { {0x70, 0x85, 0xC1}, "Hikvision" },
    { {0x18, 0x68, 0xCB}, "Hikvision" },
    { {0x54, 0xC4, 0x15}, "Hikvision" },
    { {0xD0, 0x13, 0xA5}, "Hikvision" },
    { {0xA4, 0x14, 0x37}, "Hikvision" },
    { {0x28, 0x57, 0xBE}, "Hikvision" },
    // Dahua
    { {0x90, 0x02, 0xA9}, "Dahua" },
    { {0xE0, 0x50, 0x8B}, "Dahua" },
    { {0x3C, 0xEF, 0x8C}, "Dahua" },
    { {0xBC, 0x32, 0xB2}, "Dahua" },
    // Axis Communications
    { {0x00, 0x40, 0x8C}, "Axis" },
    { {0xAC, 0xCC, 0x8E}, "Axis" },
    // Hanwha (Samsung Techwin)
    { {0x00, 0x09, 0x18}, "Hanwha" },
    { {0x7C, 0x1E, 0xB3}, "Hanwha" },
    // Reolink
    { {0xEC, 0x71, 0xDB}, "Reolink" },
    // Foscam
    { {0xC4, 0x2C, 0x03}, "Foscam" },
    // Wyze
    { {0x2C, 0xAA, 0x8E}, "Wyze" },
    { {0x7C, 0x78, 0xB2}, "Wyze" },
};

static const uint8_t OUI_TABLE_LEN =
    sizeof(OUI_CAMERA_TABLE) / sizeof(OUI_CAMERA_TABLE[0]);

// Returns true if the MAC prefix matches a known surveillance manufacturer.
inline bool oui_is_camera(const char* mac) {
    unsigned int a = 0, b = 0, c = 0;
    if (sscanf(mac, "%x:%x:%x", &a, &b, &c) != 3) return false;
    uint8_t prefix[3] = { (uint8_t)a, (uint8_t)b, (uint8_t)c };
    for (uint8_t i = 0; i < OUI_TABLE_LEN; i++) {
        if (memcmp(OUI_CAMERA_TABLE[i].prefix, prefix, 3) == 0) return true;
    }
    return false;
}

// Returns the vendor name string for a matching MAC, or nullptr if no match.
inline const char* oui_vendor(const char* mac) {
    unsigned int a = 0, b = 0, c = 0;
    if (sscanf(mac, "%x:%x:%x", &a, &b, &c) != 3) return nullptr;
    uint8_t prefix[3] = { (uint8_t)a, (uint8_t)b, (uint8_t)c };
    for (uint8_t i = 0; i < OUI_TABLE_LEN; i++) {
        if (memcmp(OUI_CAMERA_TABLE[i].prefix, prefix, 3) == 0)
            return OUI_CAMERA_TABLE[i].vendor;
    }
    return nullptr;
}
