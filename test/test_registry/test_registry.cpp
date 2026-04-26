#include <unity.h>
#include <string.h>
#include "device_registry.h"

void setUp()    { registry_init(); }
void tearDown() {}

void test_add_new_device() {
    ScanResult r;
    r.protocol = DeviceProtocol::WIFI;
    strncpy(r.mac,         "AA:BB:CC:DD:EE:FF", sizeof(r.mac));
    strncpy(r.name_or_ssid, "TestAP",           sizeof(r.name_or_ssid));
    r.channel = 6;
    r.rssi    = -70;

    registry_update(&r, 1, 1000);

    uint8_t count;
    DetectedDevice* devs = registry_get_all(count);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL_STRING("AA:BB:CC:DD:EE:FF", devs[0].mac);
    TEST_ASSERT_EQUAL(-70, (int)devs[0].rssi);
    TEST_ASSERT_EQUAL(1,   devs[0].times_seen);
}

void test_merge_same_mac_and_protocol() {
    ScanResult r;
    r.protocol = DeviceProtocol::WIFI;
    strncpy(r.mac,         "AA:BB:CC:DD:EE:FF", sizeof(r.mac));
    strncpy(r.name_or_ssid, "TestAP",           sizeof(r.name_or_ssid));
    r.channel = 6;
    r.rssi    = -70;

    registry_update(&r, 1, 1000);
    r.rssi = -60;
    registry_update(&r, 1, 2000);

    uint8_t count;
    DetectedDevice* devs = registry_get_all(count);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL(2, devs[0].times_seen);
    TEST_ASSERT_EQUAL(-60, (int)devs[0].rssi);
}

void test_different_protocols_not_merged() {
    ScanResult r;
    strncpy(r.mac,         "AA:BB:CC:DD:EE:FF", sizeof(r.mac));
    strncpy(r.name_or_ssid, "",                 sizeof(r.name_or_ssid));
    r.channel = 0;
    r.rssi    = -70;

    r.protocol = DeviceProtocol::WIFI;
    registry_update(&r, 1, 1000);
    r.protocol = DeviceProtocol::BLE;
    registry_update(&r, 1, 1000);

    uint8_t count;
    registry_get_all(count);
    TEST_ASSERT_EQUAL(2, count);
}

void test_rssi_smoothing() {
    ScanResult r;
    r.protocol = DeviceProtocol::WIFI;
    strncpy(r.mac,         "11:22:33:44:55:66", sizeof(r.mac));
    strncpy(r.name_or_ssid, "",                 sizeof(r.name_or_ssid));
    r.channel = 1;
    r.rssi    = -80;

    registry_update(&r, 1, 1000);  // first: smoothed = -80
    r.rssi = -50;
    registry_update(&r, 1, 2000);  // smoothed = 0.7*(-80) + 0.3*(-50) = -71

    uint8_t count;
    DetectedDevice* devs = registry_get_all(count);
    TEST_ASSERT_INT_WITHIN(2, -71, (int)devs[0].smoothed_rssi);
}

void test_drop_stale() {
    ScanResult r;
    r.protocol = DeviceProtocol::WIFI;
    strncpy(r.mac,         "AA:BB:CC:DD:EE:FF", sizeof(r.mac));
    strncpy(r.name_or_ssid, "",                 sizeof(r.name_or_ssid));
    r.channel = 6;
    r.rssi    = -70;

    registry_update(&r, 1, 1000);
    registry_drop_stale(1000 + STALE_TIMEOUT_MS);

    uint8_t count;
    registry_get_all(count);
    TEST_ASSERT_EQUAL(0, count);
}

void test_not_dropped_before_timeout() {
    ScanResult r;
    r.protocol = DeviceProtocol::WIFI;
    strncpy(r.mac,         "AA:BB:CC:DD:EE:FF", sizeof(r.mac));
    strncpy(r.name_or_ssid, "",                 sizeof(r.name_or_ssid));
    r.channel = 6;
    r.rssi    = -70;

    registry_update(&r, 1, 1000);
    registry_drop_stale(1000 + STALE_TIMEOUT_MS - 1);

    uint8_t count;
    registry_get_all(count);
    TEST_ASSERT_EQUAL(1, count);
}

int main(int argc, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_add_new_device);
    RUN_TEST(test_merge_same_mac_and_protocol);
    RUN_TEST(test_different_protocols_not_merged);
    RUN_TEST(test_rssi_smoothing);
    RUN_TEST(test_drop_stale);
    RUN_TEST(test_not_dropped_before_timeout);
    return UNITY_END();
}
