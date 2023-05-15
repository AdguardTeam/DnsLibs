package com.adguard.dnslibs.proxy;

import java.util.Objects;

/**
 * The subset of {@link DnsProxySettings} available for overriding on a specific listener
 */
public class ProxySettingsOverrides {
    private Boolean blockEch;

    /**
     * Set {@link DnsProxySettings#blockEch} overriding value.
     * If null, overriding is not applied.
     */
    public void setBlockEch(Boolean blockEch) {
        this.blockEch = blockEch;
    }

    /**
     * @return {@link DnsProxySettings#blockEch} overriding value
     */
    public Boolean getBlockEch() {
        return this.blockEch;
    }

    @Override
    public boolean equals(Object x) {
        if (this == x) return true;
        if (x == null || getClass() != x.getClass()) return false;
        ProxySettingsOverrides that = (ProxySettingsOverrides) x;
        return Objects.equals(this.blockEch, that.blockEch);
    }

    @Override
    public int hashCode() {
        return Objects.hash(blockEch);
    }
}
