#pragma once
#include "types.h"
#include "config.h"

void             registry_init();
void             registry_update(const ScanResult* results, uint8_t count, uint32_t now_ms);
void             registry_drop_stale(uint32_t now_ms);
DetectedDevice*  registry_get_all(uint8_t& out_count);
void             registry_set_whitelisted(const char* mac, DeviceProtocol proto, bool state);
