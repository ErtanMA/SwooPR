#include <unity.h>
#include "whitelist_store.h"

void setUp()    { whitelist_init(); }
void tearDown() {}

void test_add_and_contains() {
    TEST_ASSERT_FALSE(whitelist_contains("AA:BB:CC:DD:EE:FF"));
    whitelist_add("AA:BB:CC:DD:EE:FF");
    TEST_ASSERT_TRUE(whitelist_contains("AA:BB:CC:DD:EE:FF"));
}

void test_add_duplicate_is_idempotent() {
    whitelist_add("AA:BB:CC:DD:EE:FF");
    whitelist_add("AA:BB:CC:DD:EE:FF");
    TEST_ASSERT_TRUE(whitelist_contains("AA:BB:CC:DD:EE:FF"));
}

void test_remove_existing() {
    whitelist_add("AA:BB:CC:DD:EE:FF");
    TEST_ASSERT_TRUE(whitelist_remove("AA:BB:CC:DD:EE:FF"));
    TEST_ASSERT_FALSE(whitelist_contains("AA:BB:CC:DD:EE:FF"));
}

void test_remove_nonexistent_returns_false() {
    TEST_ASSERT_FALSE(whitelist_remove("00:00:00:00:00:00"));
}

void test_remove_middle_preserves_others() {
    whitelist_add("AA:BB:CC:DD:EE:01");
    whitelist_add("AA:BB:CC:DD:EE:02");
    whitelist_add("AA:BB:CC:DD:EE:03");

    whitelist_remove("AA:BB:CC:DD:EE:02");

    TEST_ASSERT_TRUE(whitelist_contains("AA:BB:CC:DD:EE:01"));
    TEST_ASSERT_FALSE(whitelist_contains("AA:BB:CC:DD:EE:02"));
    TEST_ASSERT_TRUE(whitelist_contains("AA:BB:CC:DD:EE:03"));
}

void test_unknown_mac_not_found() {
    whitelist_add("AA:BB:CC:DD:EE:FF");
    TEST_ASSERT_FALSE(whitelist_contains("11:22:33:44:55:66"));
}

int main(int argc, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_add_and_contains);
    RUN_TEST(test_add_duplicate_is_idempotent);
    RUN_TEST(test_remove_existing);
    RUN_TEST(test_remove_nonexistent_returns_false);
    RUN_TEST(test_remove_middle_preserves_others);
    RUN_TEST(test_unknown_mac_not_found);
    return UNITY_END();
}
