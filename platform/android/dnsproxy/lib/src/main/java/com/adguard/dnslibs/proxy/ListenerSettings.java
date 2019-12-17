package com.adguard.dnslibs.proxy;

import java.util.Objects;

public class ListenerSettings {
    public enum Protocol {
        // MUST keep names and ordinals in sync with ag::listener_protocol
        UDP,
        TCP,
    }

    private String address = "::";
    private int port = 53;
    private Protocol protocol = Protocol.UDP;
    private boolean persistent = false;
    private long idleTimeout = 3000;

    /**
     * @return The address to listen on.
     */
    public String getAddress() {
        return address;
    }

    /**
     * @param address The address to listen on.
     */
    public void setAddress(String address) {
        this.address = address;
    }

    /**
     * @return The port to listen on.
     */
    public int getPort() {
        return port;
    }

    /**
     * @param port The port to listen on.
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * @return The protocol to listen for.
     */
    public Protocol getProtocol() {
        return protocol;
    }

    /**
     * @param protocol The protocol to listen for.
     */
    public void setProtocol(Protocol protocol) {
        this.protocol = Objects.requireNonNull(protocol, "protocol");
    }

    /**
     * @return If {@code true}, don't close the TCP connection after sending the first response.
     */
    public boolean isPersistent() {
        return persistent;
    }

    /**
     * @param persistent If {@code true}, don't close the TCP connection after sending the first response.
     */
    public void setPersistent(boolean persistent) {
        this.persistent = persistent;
    }

    /**
     * @return The amount of time, in milliseconds, since the last request received after which the connection will be closed.
     */
    public long getIdleTimeout() {
        return idleTimeout;
    }

    /**
     * @param idleTimeout The amount of time, in milliseconds, since the last request received after which the connection will be closed.
     */
    public void setIdleTimeout(long idleTimeout) {
        this.idleTimeout = idleTimeout;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ListenerSettings that = (ListenerSettings) o;
        return port == that.port &&
                persistent == that.persistent &&
                idleTimeout == that.idleTimeout &&
                Objects.equals(address, that.address) &&
                protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(address, port, protocol, persistent, idleTimeout);
    }
}
