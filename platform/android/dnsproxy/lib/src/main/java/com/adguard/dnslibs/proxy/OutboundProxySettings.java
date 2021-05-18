package com.adguard.dnslibs.proxy;

import java.net.InetSocketAddress;
import java.util.Objects;

public class OutboundProxySettings {
    public enum Protocol {
        // MUST keep names and ordinals in sync with ag::outbound_proxy_protocol

        /** Plain HTTP proxy */
        HTTP_CONNECT,
        /** HTTPs proxy */
        HTTPS_CONNECT,
        /** Socks4 proxy */
        SOCKS4,
        /** Socks5 proxy without UDP support */
        SOCKS5,
        /** Socks5 proxy with UDP support */
        SOCKS5_UDP,
    }

    public static class AuthInfo {
        private final String username;
        private final String password;

        public AuthInfo(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthInfo that = (AuthInfo)o;
            return Objects.equals(this.username, that.username)
                    && Objects.equals(this.password, that.password);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.username, this.password);
        }
    }

    private final Protocol protocol;
    private final InetSocketAddress address;
    private final AuthInfo authInfo;
    private final boolean trustAnyCertificate;

    /**
     * @param protocol The proxy protocol
     * @param address The proxy server address
     */
    public OutboundProxySettings(Protocol protocol, InetSocketAddress address) {
        this.protocol = protocol;
        this.address = address;
        this.authInfo = null;
        this.trustAnyCertificate = false;
    }

    /**
     * @param protocol The proxy protocol
     * @param address The proxy server address
     * @param authInfo The authentication information
     * @param trustAnyCertificate If true and the proxy connection is secure, the certificate won't be verified
     */
    public OutboundProxySettings(Protocol protocol, InetSocketAddress address,
                                 AuthInfo authInfo, boolean trustAnyCertificate) {
        this.protocol = protocol;
        this.address = address;
        this.authInfo = authInfo;
        this.trustAnyCertificate = trustAnyCertificate;
    }

    /**
     * @return The proxy protocol
     */
    public Protocol getProtocol() {
        return protocol;
    }

    /**
     * @return The proxy server address
     */
    public InetSocketAddress getAddress() {
        return address;
    }

    /**
     * @return The authentication information
     */
    public AuthInfo getAuthInfo() {
        return authInfo;
    }

    /**
     * @return If the proxy server's certificate verified
     */
    public boolean isTrustAnyCertificate() {
        return trustAnyCertificate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OutboundProxySettings that = (OutboundProxySettings)o;
        return this.protocol == that.protocol
                && Objects.equals(this.address, that.address)
                && Objects.equals(this.authInfo, that.authInfo)
                && this.trustAnyCertificate == that.trustAnyCertificate;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.protocol, this.address, this.authInfo, this.trustAnyCertificate);
    }
}
