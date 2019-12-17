package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class UpstreamSettings {
    private String address;
    private List<String> bootstrap = new ArrayList<>();
    private long timeout;
    private byte[] serverIp;

    /**
     * @return The DNS server's address.
     */
    public String getAddress() {
        return address;
    }

    /**
     * @param address The DNS server's address.
     */
    public void setAddress(String address) {
        this.address = address;
    }

    /**
     * @return List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any).
     */
    public List<String> getBootstrap() {
        return bootstrap;
    }

    /**
     * @return Default upstream timeout in milliseconds. Also, it is used as a timeout for bootstrap DNS requests.
     * {@code timeout = 0} means infinite timeout.
     */
    public long getTimeout() {
        return timeout;
    }

    /**
     * @param timeout Default upstream timeout in milliseconds. Also, it is used as a timeout for bootstrap DNS requests.
     *                {@code timeout = 0} means infinite timeout.
     */
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    /**
     * @return Resolver's IP address. In the case if it's specified, bootstrap DNS servers won't be used at all.
     */
    public byte[] getServerIp() {
        return serverIp;
    }

    /**
     * @param serverIp Resolver's IP address. In the case if it's specified, bootstrap DNS servers won't be used at all.
     */
    public void setServerIp(byte[] serverIp) {
        this.serverIp = serverIp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UpstreamSettings that = (UpstreamSettings) o;
        return timeout == that.timeout &&
                Objects.equals(address, that.address) &&
                bootstrap.equals(that.bootstrap) &&
                Arrays.equals(serverIp, that.serverIp);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(address, bootstrap, timeout);
        result = 31 * result + Arrays.hashCode(serverIp);
        return result;
    }
}
