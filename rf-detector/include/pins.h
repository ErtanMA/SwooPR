#pragma once

// OLED display (SSD1306 / SH1106) — I2C
constexpr int PIN_OLED_SDA = 8;
constexpr int PIN_OLED_SCL = 9;

// Buttons — active-low, internal pull-up enabled
constexpr int PIN_BTN_MODE   = 4;
constexpr int PIN_BTN_SELECT = 5;
constexpr int PIN_BTN_ACTION = 6;

// Buzzer / vibration motor — must be PWM-capable
constexpr int PIN_BUZZER = 7;
