package com.adguard.dnslibs.proxy;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class OutboundProxySettings {
    public enum Protocol {
        // MUST keep names and ordinals in sync with ag::OutboundProxyProtocol

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
    private final String address;
    private final int port;
    private final List<String> bootstrap;
    private final AuthInfo authInfo;
    private final boolean trustAnyCertificate;
    private final boolean ignoreIfUnavailable;

    /**
     * @param protocol The proxy protocol
     * @param address The proxy server address
     */
    public OutboundProxySettings(Protocol protocol, InetSocketAddress address) {
        this.protocol = protocol;
        this.address = address.getAddress().toString();
        this.port = address.getPort();
        this.bootstrap = new ArrayList<>();
        this.authInfo = null;
        this.trustAnyCertificate = false;
        this.ignoreIfUnavailable = false;
    }

    /**
     * @param protocol The proxy protocol
     * @param address The proxy server IP address or hostname
     * @param port The proxy server port (0 means default)
     * @param bootstrap List of the DNS server URLs to be used to resolve a hostname in the proxy server address.
     *                  The URLs MUST contain the resolved server addresses, not hostnames.
     *                  E.g. `https://94.140.14.14` is correct, while `dns.adguard.com:53` is not.
     *                  MUST NOT be empty in case the `address` is a hostname.
     * @param authInfo The authentication information
     * @param trustAnyCertificate If true and the proxy connection is secure, the certificate won't be verified
     * @param ignoreIfUnavailable Whether the DNS proxy should ignore the outbound proxy and route
     *                            queries directly to target hosts even if it's determined as unavailable
     */
    public OutboundProxySettings(Protocol protocol, String address, int port,
                                 List<String> bootstrap, AuthInfo authInfo,
                                 boolean trustAnyCertificate, boolean ignoreIfUnavailable) {
        this.protocol = protocol;
        this.address = address;
        this.port = port;
        if (null == bootstrap) {
            this.bootstrap = new ArrayList<>();
        } else {
            this.bootstrap = new ArrayList<>(bootstrap);
        }
        this.authInfo = authInfo;
        this.trustAnyCertificate = trustAnyCertificate;
        this.ignoreIfUnavailable = ignoreIfUnavailable;
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
    public String getAddress() {
        return address;
    }

    /**
     * @return The proxy server port
     */
    public int getPort() {
        return port;
    }

    /**
     * @return The bootstrap servers
     */
    public List<String> getBootstrap() {
        return bootstrap;
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

    /**
     * @return Whether the DNS proxy should continue trying to go through the proxy
     *         even if it's determined as unavailable
     */
    public boolean isIgnoreIfUnavailable() {
        return ignoreIfUnavailable;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OutboundProxySettings that = (OutboundProxySettings)o;
        return this.protocol == that.protocol
                && Objects.equals(this.address, that.address)
                && this.port == that.port
                && this.bootstrap.equals(that.bootstrap)
                && Objects.equals(this.authInfo, that.authInfo)
                && this.trustAnyCertificate == that.trustAnyCertificate
                && this.ignoreIfUnavailable == that.ignoreIfUnavailable;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.protocol, this.address, this.port, this.bootstrap, this.authInfo,
                this.trustAnyCertificate, this.ignoreIfUnavailable);
    }
}
