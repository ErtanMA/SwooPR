#include <unity.h>
#include <string.h>
#include "threat_engine.h"
#include "config.h"

void setUp()    {}
void tearDown() {}

static DetectedDevice make_device(int8_t rssi, bool whitelisted,
                                   uint16_t times_seen, bool hidden) {
    DetectedDevice d = {};
    d.protocol      = DeviceProtocol::WIFI;
    strncpy(d.mac, "AA:BB:CC:DD:EE:FF", sizeof(d.mac));
    d.rssi          = rssi;
    d.smoothed_rssi = rssi;
    d.times_seen    = times_seen;
    d.whitelisted   = whitelisted;
    if (!hidden)
        strncpy(d.name_or_ssid, "TestAP", sizeof(d.name_or_ssid));
    return d;
}

void test_whitelisted_scores_zero() {
    DetectedDevice d = make_device(-50, true, 10, false);
    threat_score_all(&d, 1);
    TEST_ASSERT_EQUAL(0, d.threat_score);
}

void test_strong_beats_medium_beats_weak() {
    DetectedDevice arr[3];
    arr[0] = make_device(-50, false, 1, false);  // strong: above RSSI_STRONG_THRESHOLD
    arr[1] = make_device(-70, false, 1, false);  // medium: between thresholds
    arr[2] = make_device(-85, false, 1, false);  // weak: below RSSI_MEDIUM_THRESHOLD

    threat_score_all(arr, 3);

    TEST_ASSERT_GREATER_THAN(arr[1].threat_score, arr[0].threat_score);
    TEST_ASSERT_GREATER_THAN(arr[2].threat_score, arr[1].threat_score);
}

void test_hidden_ssid_scores_higher() {
    DetectedDevice visible = make_device(-70, false, 1, false);
    DetectedDevice hidden  = make_device(-70, false, 1, true);

    threat_score_all(&visible, 1);
    threat_score_all(&hidden,  1);

    TEST_ASSERT_GREATER_THAN(visible.threat_score, hidden.threat_score);
}

void test_score_capped_at_max() {
    DetectedDevice d = make_device(-50, false, 0xFFFF, true);
    threat_score_all(&d, 1);
    TEST_ASSERT_LESS_OR_EQUAL(THREAT_SCORE_MAX, d.threat_score);
}

void test_sort_descending() {
    DetectedDevice arr[3];
    arr[0] = make_device(-85, false, 1, false);
    arr[1] = make_device(-50, false, 1, false);
    arr[2] = make_device(-70, false, 1, false);

    threat_score_all(arr, 3);
    threat_sort(arr, 3);

    TEST_ASSERT_GREATER_OR_EQUAL(arr[1].threat_score, arr[0].threat_score);
    TEST_ASSERT_GREATER_OR_EQUAL(arr[2].threat_score, arr[1].threat_score);
}

void test_times_seen_contributes_to_score() {
    DetectedDevice few  = make_device(-85, false, 1,  false);
    DetectedDevice many = make_device(-85, false, 20, false);

    threat_score_all(&few,  1);
    threat_score_all(&many, 1);

    TEST_ASSERT_GREATER_THAN(few.threat_score, many.threat_score);
}

int main(int argc, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_whitelisted_scores_zero);
    RUN_TEST(test_strong_beats_medium_beats_weak);
    RUN_TEST(test_hidden_ssid_scores_higher);
    RUN_TEST(test_score_capped_at_max);
    RUN_TEST(test_sort_descending);
    RUN_TEST(test_times_seen_contributes_to_score);
    return UNITY_END();
}
