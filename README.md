# SwooPR

Handheld 2.4 GHz Wi-Fi & BLE transmitter detector. Made for detecting and warning about secret microphones or cameras in AirBnBs or other temporary accommodation.

## Hardware
- ESP32-S3 dev board
- SSD1306 / SH1106 128×64 OLED (I2C)
- 3 momentary buttons
- Buzzer or vibration motor
- Li-ion battery

## Build
```bash
pio run             # compile
pio run -t upload   # flash
pio device monitor  # serial output at 115200
pio test -e native  # unit tests (no hardware needed)
```
