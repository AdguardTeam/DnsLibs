package com.adguard.dnslibs.proxy;

import java.util.Objects;

/**
 * DNS Stamp
 */
public class DnsStamp {

    /**
     * ProtoType is a stamp protocol type
     */
    public enum ProtoType {
        /** plain is plain DNS */
        PLAIN,

        /** dnscrypt is DNSCrypt */
        DNSCRYPT,

        /** doh is DNS-over-HTTPS */
        DOH,

        /** tls is DNS-over-TLS */
        TLS
    };

    private ProtoType proto; /** Protocol */
    private String serverAddr; /** Server address */
    private String providerName; /** Provider name */
    private String path; /** Path (for DOH) */

    public DnsStamp() {}

    public DnsStamp(ProtoType proto, String serverAddr, String providerName, String path) {
        setProto(proto);
        setServerAddr(serverAddr);
        setProviderName(providerName);
        setPath(path);
    }

    public ProtoType getProto() {
        return proto;
    }

    public void setProto(ProtoType proto) {
        this.proto = proto;
    }

    public String getServerAddr() {
        return serverAddr;
    }

    public void setServerAddr(String serverAddr) {
        this.serverAddr = serverAddr;
    }

    public String getProviderName() {
        return providerName;
    }

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DnsStamp dnsStamp = (DnsStamp) o;
        return getProto() == dnsStamp.getProto() &&
                Objects.equals(getServerAddr(), dnsStamp.getServerAddr()) &&
                Objects.equals(getProviderName(), dnsStamp.getProviderName()) &&
                Objects.equals(getPath(), dnsStamp.getPath());
    }
}
