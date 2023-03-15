package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class UpstreamSettings {
    private String address;
    private List<String> bootstrap = new ArrayList<>();
    private long timeoutMs;
    private byte[] serverIp;
    private int id;
    private String outboundInterfaceName;
    private List<String> fingerprints = new ArrayList<>();

    public UpstreamSettings() {}

    /**
     * Creates UpstreamSettings
     * @param address   The DNS server's address.
     * @param bootstrap List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any).
     * @param timeoutMs Default upstream timeout in milliseconds. Also, it is used as a timeout for bootstrap DNS requests.
     *                  {@code timeout = 0} means infinite timeout.
     * @param serverIp  Resolver's IP address. In the case if it's specified, bootstrap DNS servers won't be used at all.
     * @param id        User-provided ID
     */
    public UpstreamSettings(String address, List<String> bootstrap,
                            long timeoutMs, byte[] serverIp, int id) {
        setAddress(address);
        setBootstrap(bootstrap);
        setTimeoutMs(timeoutMs);
        setServerIp(serverIp);
        setId(id);
    }

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
     * @param bootstrap List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any).
     */
    public void setBootstrap(List<String> bootstrap) {
        if (null == bootstrap) {
            this.bootstrap.clear();
            return;
        }
        this.bootstrap = new ArrayList<>(bootstrap);
    }

    /**
     * @return Default upstream timeout in milliseconds. Also, it is used as a timeout for bootstrap DNS requests.
     * {@code timeout = 0} means infinite timeout.
     */
    public long getTimeoutMs() {
        return timeoutMs;
    }

    /**
     * @param timeoutMs Default upstream timeout in milliseconds. Also, it is used as a timeout for bootstrap DNS requests.
     *                  {@code timeout = 0} means infinite timeout.
     */
    public void setTimeoutMs(long timeoutMs) {
        this.timeoutMs = timeoutMs;
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

    /**
     * @return User-provided ID for this upstream
     */
    public int getId() {
        return id;
    }

    /**
     * @param id User-provided ID for this upstream
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * @return name of the network interface that traffic is routed through, or {@code null}
     */
    public String getOutboundInterfaceName() {
        return outboundInterfaceName;
    }

    /**
     * @param outboundInterfaceName name of the network interface to route traffic through,
     *                              or {@code null} or empty to use the default
     */
    public void setOutboundInterfaceName(String outboundInterfaceName) {
        this.outboundInterfaceName = outboundInterfaceName;
    }

    public List<String> getFingerprints() {
        return fingerprints;
    }

    public void setFingerprints(List<String> certFingerprints) {
        this.fingerprints = certFingerprints;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UpstreamSettings that = (UpstreamSettings) o;
        return timeoutMs == that.timeoutMs &&
                id == that.id &&
                Objects.equals(address, that.address) &&
                bootstrap.equals(that.bootstrap) &&
                Arrays.equals(serverIp, that.serverIp) &&
                Objects.equals(outboundInterfaceName, that.outboundInterfaceName) &&
                fingerprints.equals(that.fingerprints);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timeoutMs, id, address, bootstrap, serverIp, outboundInterfaceName, fingerprints);
    }
}
