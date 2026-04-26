#pragma once
#include "types.h"

void    wifi_scanner_init();
uint8_t wifi_scanner_scan(ScanResult* out, uint8_t max_count);
