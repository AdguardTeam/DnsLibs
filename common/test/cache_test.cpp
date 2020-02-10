#include <gtest/gtest.h>
#include <ag_cache.h>

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
        auto v = cache.get(i);
        ASSERT_TRUE(v);
        ASSERT_EQ(*v, std::to_string(i));
    }

    // check that cache grows no more
    for (size_t i = CACHE_SIZE; i < CACHE_SIZE * 2; ++i) {
        cache.insert(i, std::to_string(i));
        ASSERT_EQ(cache.size(), CACHE_SIZE);
    }

    // check that old values were displaced
    for (size_t i = 0; i < CACHE_SIZE; ++i) {
        ASSERT_FALSE(cache.get(i));
    }

    // check that new values were inserted
    for (size_t i = CACHE_SIZE; i < CACHE_SIZE * 2; ++i) {
        auto v = cache.get(i);
        ASSERT_TRUE(v);
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
            ASSERT_FALSE(cache.get(i));
        } else {
            ASSERT_TRUE(cache.get(i));
        }
    }
}

TEST_F(lru_cache_test, make_lru) {
    auto acc = cache.get(CACHE_SIZE - 1);
    ASSERT_TRUE(acc);
    cache.make_lru(acc);
    cache.insert(1234, "1234");

    // Check that the MRU entry that has been made LRU has been pushed out of the cache
    ASSERT_FALSE(cache.get(CACHE_SIZE - 1));
    ASSERT_TRUE(cache.get(1234));
    ASSERT_EQ(CACHE_SIZE, cache.size());
}

TEST_F(lru_cache_test, displace_order) {
    // check that the least recent used values are being displaced first
    size_t j = 0;
    size_t i = CACHE_SIZE;
    for (; i < CACHE_SIZE * 2; ++i, ++j) {
        cache.insert(i, std::to_string(i));
        ASSERT_FALSE(cache.get(j));
    }
}

TEST_F(lru_cache_test, refresh_on_insert) {
    // check that inserting existing key refreshes entry
    cache.insert(0, "42");
    cache.insert(CACHE_SIZE, std::to_string(CACHE_SIZE));

    ASSERT_TRUE(cache.get(0));
    ASSERT_EQ(*cache.get(0), "42");
    ASSERT_FALSE(cache.get(1));
    ASSERT_TRUE(cache.get(CACHE_SIZE));
}

TEST_F(lru_cache_test, refresh_on_get) {
    // check that getting key refreshes entry
    ASSERT_TRUE(cache.get(0));
    cache.insert(CACHE_SIZE, std::to_string(CACHE_SIZE));

    ASSERT_TRUE(cache.get(0));
    ASSERT_FALSE(cache.get(1));
    ASSERT_TRUE(cache.get(CACHE_SIZE));
}

TEST_F(lru_cache_test, update_capacity) {
    // check that changing capacity to lower value removes LRU entries
    cache.set_capacity(CACHE_SIZE / 2);
    ASSERT_EQ(cache.size(), CACHE_SIZE / 2);

    for (size_t i = 0; i < CACHE_SIZE / 2; ++i) {
        ASSERT_FALSE(cache.get(i)) << i << std::endl;
    }
}
