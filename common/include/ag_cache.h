#pragma once

#include <unordered_map>
#include <list>

namespace ag {

/**
 * Generic cache with least-recently-used eviction policy
 */
template <typename Key, typename Val>
class lru_cache {
public:
    using node = std::pair<const Key, Val>;

    static constexpr size_t DEFAULT_CAPACITY = 128;

    /**
     * Initialize a new cache
     * @param max_size cache capacity, 0 means default
     */
    explicit lru_cache(size_t max_size = DEFAULT_CAPACITY) : m_max_size{max_size} {
        set_capacity(max_size);
    }

    /**
     * Insert a new key-value pair or update an existing one.
     * The new or updated entry will become most-recently-used.
     * @param k key
     * @param v value
     * @return false if an entry with this key already exists and was updated, or
     *         true if an entry with this key didn't exist.
     */
    bool insert(Key k, Val v) {
        auto i = m_mapped_values.find(k);
        if (i != m_mapped_values.end()) {
            m_key_values.splice(m_key_values.begin(), m_key_values, i->second);
            i->second->second = std::move(v);
            i->second = m_key_values.begin();
            return false;
        } else {
            assert(m_max_size);
            if (m_key_values.size() == m_max_size) {
                m_mapped_values.erase(m_key_values.back().first);
                m_key_values.pop_back();
            }
            m_key_values.push_front(std::make_pair(k, std::move(v)));
            m_mapped_values.emplace(std::make_pair(std::move(k), m_key_values.begin()));
            return true;
        }
    }

    /**
     * Get the value associated with the given key.
     * The corresponding entry will become most-recently-used.
     * The returned pointer will only be valid until the next modification of the cache!
     * @param k the key
     * @return pointer to the found value, or
     *         nullptr if nothing was found
     */
    const Val *get(const Key &k) const {
        auto i = m_mapped_values.find(k);
        if (i != m_mapped_values.end()) {
            m_key_values.splice(m_key_values.begin(), m_key_values, i->second);
            return &m_key_values.front().second;
        } else {
            return nullptr;
        }
    }

    /**
     * Delete the value with the given key from the cache
     * @param k the key
     */
    void erase(const Key &k) {
        auto i = m_mapped_values.find(k);
        if (i != m_mapped_values.end()) {
            m_key_values.erase(i->second);
            m_mapped_values.erase(i);
        }
    }

    /**
     * Clear the cache
     */
    void clear() {
        m_key_values.clear();
        m_mapped_values.clear();
    }

    /**
     * @return current cache size
     */
    size_t size() const {
        return m_key_values.size();
    }

    /**
     * @return maximum cache size
     */
    size_t max_size() const {
        return m_max_size;
    }

    /**
     * Set cache capacity. If the new capacity is less than the current,
     * the least recenlty used entries are removed from the cache.
     * @param max_size new capacity, 0 means default capacity
     */
    void set_capacity(size_t max_size) {
        if (!max_size) {
            max_size = DEFAULT_CAPACITY;
        }
        if (max_size < size()) {
            size_t diff = size() - max_size;
            for (size_t i = 0; i < diff; i++) {
                m_mapped_values.erase(m_key_values.back().first);
                m_key_values.pop_back();
            }
        }
        m_max_size = max_size;
    }

private:
    /** Cache capacity */
    size_t m_max_size;
    mutable std::list<node> m_key_values;
    mutable std::unordered_map<Key, typename decltype(m_key_values)::iterator> m_mapped_values;
};

} // namespace ag
