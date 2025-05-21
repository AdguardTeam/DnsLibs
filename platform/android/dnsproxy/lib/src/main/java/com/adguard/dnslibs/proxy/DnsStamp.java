package com.adguard.dnslibs.proxy;

import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
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
        TLS,

        /** doq is DNS-over-QUIC */
        DOQ,
    }

    public enum InformalProperties {
        /** Resolver does DNSSEC validation */
        DNSSEC(1),
        /** Resolver does not record logs */
        NO_LOG(1 << 1),
        /** Resolver doesn't intentionally block domains */
        NO_FILTER(1 << 2),
        ;

        private final int flagValue;

        InformalProperties(int flagValue) {
            this.flagValue = flagValue;
        }

        private static EnumSet<InformalProperties> toEnumSet(int flags) {
            EnumSet<InformalProperties> enumSet = EnumSet.noneOf(InformalProperties.class);
            for (InformalProperties prop : values()) {
                if (prop.flagValue == 0) continue;
                if ((flags & prop.flagValue) != 0) {
                    enumSet.add(prop);
                }
            }
            return enumSet;
        }
    }

    /** Protocol */
    private ProtoType proto;
    /** Server address */
    private String serverAddr;
    /** Provider name */
    private String providerName;
    /** Path (for DOH) */
    private String path;
    /** DNSCrypt provider’s Ed25519 public key */
    private byte[] serverPublicKey;
    /** Server properties */
    private EnumSet<InformalProperties> properties;
    /**
     * Hash is the SHA256 digest of one of the TBS certificate found in the validation chain,
     * typically the certificate used to sign the resolver’s certificate. Multiple hashes can
     * be provided for seamless rotations.
     */
    private ArrayList<byte[]> hashes;

    public DnsStamp() {}

    public DnsStamp(ProtoType proto, String serverAddr, String providerName, String path,
                    byte[] serverPublicKey, EnumSet<InformalProperties> properties, ArrayList<byte[]> hashes) {
        setProto(proto);
        setServerAddr(serverAddr);
        setProviderName(providerName);
        setPath(path);
        setServerPublicKey(serverPublicKey);
        setProperties(properties);
        setHashes(hashes);
    }

    /**
     * Parses a DNS stamp string and returns a instance of DNS stamp or throws on error
     * @param stampStr DNS stamp string
     * @throws IllegalArgumentException with explanation
     * @return stamp instance
     */
    public static DnsStamp parse(String stampStr) throws IllegalArgumentException {
        Objects.requireNonNull(stampStr, "stampStr");
        return parse0(stampStr);
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

    public byte[] getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(byte[] serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    @Nullable
    public EnumSet<InformalProperties> getProperties() {
        return properties;
    }

    public void setProperties(EnumSet<InformalProperties> properties) {
        this.properties = properties;
    }

    public ArrayList<byte[]> getHashes() {
        return hashes;
    }

    public void setHashes(ArrayList<byte[]> hashes) {
        this.hashes = hashes;
    }

    /**
     * A URL representation of this stamp which can be used
     * as a valid {@link UpstreamSettings} address.
     */
    public native String getPrettyUrl();
    /**
     * A URL representation of this stamp which is prettier, but can NOT be used
     * as a valid {@link UpstreamSettings} address.
     */
    public native String getPrettierUrl();

    @Override
    public native String toString();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DnsStamp dnsStamp = (DnsStamp) o;
        return getProto() == dnsStamp.getProto() &&
                Objects.equals(getServerAddr(), dnsStamp.getServerAddr()) &&
                Objects.equals(getProviderName(), dnsStamp.getProviderName()) &&
                Objects.equals(getPath(), dnsStamp.getPath()) &&
                Arrays.equals(getServerPublicKey(), dnsStamp.getServerPublicKey()) &&
                Objects.equals(getProperties(), dnsStamp.getProperties()) &&
                this.hashesEqual(dnsStamp);
    }

    private boolean hashesEqual(final DnsStamp dnsStamp) {
        if (this.hashes == null) {
            return dnsStamp.hashes == null;
        }
        if (dnsStamp.hashes == null) {
            return false;
        }
        if (this.hashes.size() != dnsStamp.hashes.size()) {
            return false;
        }

        for (int i = 0; i != this.hashes.size(); ++i) {
            if (!Arrays.equals(this.hashes.get(i), dnsStamp.hashes.get(i))) {
                return false;
            }
        }

        return true;
    }

    private static native DnsStamp parse0(String string) throws IllegalArgumentException;
}
