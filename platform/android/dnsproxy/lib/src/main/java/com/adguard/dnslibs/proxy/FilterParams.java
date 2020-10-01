package com.adguard.dnslibs.proxy;

import java.util.Objects;

public class FilterParams {
    private int id;
    private String data;
    private boolean inMemory;

    public FilterParams() {}

    /**
     * Creates FilterParams
     * @param id       filter id
     * @param data     path to file or actual rules as string
     * @param inMemory if {@code true}, {@code data} is actual rules,
     *                 otherwise {@code cata} is path to file with rules
     */
    public FilterParams(int id, String data, boolean inMemory) {
        this.id = id;
        this.data = data;
        this.inMemory = inMemory;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public boolean isInMemory() {
        return inMemory;
    }

    public void setInMemory(boolean inMemory) {
        this.inMemory = inMemory;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FilterParams that = (FilterParams) o;
        return id == that.id &&
                inMemory == that.inMemory &&
                Objects.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, data, inMemory);
    }
}
