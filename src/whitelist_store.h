#pragma once

void whitelist_init();
bool whitelist_add(const char* mac);
bool whitelist_remove(const char* mac);
bool whitelist_contains(const char* mac);
