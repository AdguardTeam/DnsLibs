#include "gtest/gtest.h"
#include "ag_cache.h"


static constexpr size_t CACHE_SIZE = 1000u;

class lru_cache_test : public ::testing::Test {
public:
    lru_cache_test() : cache(CACHE_SIZE) {}

protected:
    ag::lru_cache<int, std::string> cache;

    void SetUp() override {
        for (size_t i = 0; i < CACHE_SIZE; ++i) {
            cache.insert(i, std::to_string(i));
            ASSERT_EQ(cache.size(), i + 1);
        }
    }

    void TearDown() override {
        cache.clear();
    }
};

TEST_F(lru_cache_test, clear) {
    ASSERT_NE(cache.size(), 0u);
    cache.clear();
    ASSERT_EQ(cache.size(), 0u);
}

TEST_F(lru_cache_test, insert_and_get) {
    // check that values were inserted
    for (size_t i = 0; i < CACHE_SIZE; ++i) {
        const std::string *v = cache.get(i);
        ASSERT_NE(v, nullptr);
        ASSERT_EQ(*v, std::to_string(i));
    }

    // check that cache grows no more
    for (size_t i = CACHE_SIZE; i < CACHE_SIZE * 2; ++i) {
        cache.insert(i, std::to_string(i));
        ASSERT_EQ(cache.size(), CACHE_SIZE);
    }

    // check that old values were displaced
    for (size_t i = 0; i < CACHE_SIZE; ++i) {
        ASSERT_EQ(cache.get(i), nullptr);
    }

    // check that new values were inserted
    for (size_t i = CACHE_SIZE; i < CACHE_SIZE * 2; ++i) {
        const std::string *v = cache.get(i);
        ASSERT_NE(v, nullptr);
        ASSERT_EQ(*v, std::to_string(i));
    }
}

TEST_F(lru_cache_test, erase) {
    // erase every second entry
    for (size_t i = 0; i < CACHE_SIZE; i += 2) {
        cache.erase(i);
    }

    // check that size corresponds to the entries number
    ASSERT_EQ(cache.size(), CACHE_SIZE / 2);

    // check that erased entries were deleted and other ones are still in cache
    for (size_t i = 0; i < CACHE_SIZE; ++i) {
        if ((i % 2) == 0) {
            ASSERT_EQ(cache.get(i), nullptr);
        } else {
            ASSERT_NE(cache.get(i), nullptr);
        }
    }
}

TEST_F(lru_cache_test, displace_order) {
    // check that the least recent used values are being displaced first
    size_t j = 0;
    size_t i = CACHE_SIZE;
    for (; i < CACHE_SIZE * 2; ++i, ++j) {
        cache.insert(i, std::to_string(i));
        ASSERT_EQ(cache.get(j), nullptr);
    }
}

TEST_F(lru_cache_test, refresh_on_insert) {
    // check that inserting existing key refreshes entry
    cache.insert(0, "42");
    cache.insert(CACHE_SIZE, std::to_string(CACHE_SIZE));

    ASSERT_NE(cache.get(0), nullptr);
    ASSERT_EQ(*cache.get(0), "42");
    ASSERT_EQ(cache.get(1), nullptr);
    ASSERT_NE(cache.get(CACHE_SIZE), nullptr);
}

TEST_F(lru_cache_test, refresh_on_get) {
    // check that getting key refreshes entry
    ASSERT_NE(cache.get(0), nullptr);
    cache.insert(CACHE_SIZE, std::to_string(CACHE_SIZE));

    ASSERT_NE(cache.get(0), nullptr);
    ASSERT_EQ(cache.get(1), nullptr);
    ASSERT_NE(cache.get(CACHE_SIZE), nullptr);
}

TEST_F(lru_cache_test, update_capacity) {
    // check that changing capacity to lower value removes LRU entries
    cache.set_capacity(CACHE_SIZE / 2);
    ASSERT_EQ(cache.size(), CACHE_SIZE / 2);

    for (size_t i = 0; i < CACHE_SIZE / 2; ++i) {
        ASSERT_EQ(cache.get(i), nullptr) << i << std::endl;
    }
}
