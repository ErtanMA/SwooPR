#pragma once
#include "types.h"

void    ble_scanner_init();
uint8_t ble_scanner_scan(ScanResult* out, uint8_t max_count);
