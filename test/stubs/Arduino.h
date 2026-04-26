#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdarg>

// Minimal Serial stub for native unit tests — routes printf/println to stdout
struct _FakeSerial {
    void printf(const char* fmt, ...) const {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
    void println(const char* s) const { puts(s); }
    void begin(unsigned long) const {}
};

static _FakeSerial Serial;
