package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class UpstreamSettings {
    private String address;
    private List<String> bootstrap = new ArrayList<>();
    private List<byte[]> serverIps = new ArrayList<>();
    private int id;
    private String outboundInterfaceName;
    private List<String> fingerprints = new ArrayList<>();

    public UpstreamSettings() {}

    /**
     * Creates UpstreamSettings
     * @param address   The DNS server's address.
     * @param bootstrap List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any).
     * @param serverIps Resolver's IP addresses, in the order of preference. Each address is 4 bytes (IPv4)
     *                  or 16 bytes (IPv6). In the case if it's specified, bootstrap DNS servers won't be used at all.
     * @param id        User-provided ID
     */
    public UpstreamSettings(String address, List<String> bootstrap, List<byte[]> serverIps, int id) {
        setAddress(address);
        setBootstrap(bootstrap);
        setServerIps(serverIps);
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
     * @return Resolver's IP addresses, in the order of preference.
     *         In the case if it's specified, bootstrap DNS servers won't be used at all.
     */
    public List<byte[]> getServerIps() {
        return serverIps;
    }

    /**
     * @param serverIps Resolver's IP addresses, in the order of preference. Each address is 4 bytes (IPv4)
     *                  or 16 bytes (IPv6). In the case if it's specified, bootstrap DNS servers won't be used at all.
     */
    public void setServerIps(List<byte[]> serverIps) {
        if (null == serverIps) {
            this.serverIps.clear();
            return;
        }
        this.serverIps = new ArrayList<>(serverIps);
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
        return id == that.id &&
                Objects.equals(address, that.address) &&
                bootstrap.equals(that.bootstrap) &&
                serverIpsEqual(serverIps, that.serverIps) &&
                Objects.equals(outboundInterfaceName, that.outboundInterfaceName) &&
                fingerprints.equals(that.fingerprints);
    }

    @Override
    public int hashCode() {
        int serverIpsHash = 1;
        for (byte[] ip : serverIps) {
            serverIpsHash = 31 * serverIpsHash + Arrays.hashCode(ip);
        }
        return Objects.hash(id, address, bootstrap, serverIpsHash, outboundInterfaceName, fingerprints);
    }

    private static boolean serverIpsEqual(List<byte[]> a, List<byte[]> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (int i = 0; i < a.size(); i++) {
            if (!Arrays.equals(a.get(i), b.get(i))) {
                return false;
            }
        }
        return true;
    }
}
