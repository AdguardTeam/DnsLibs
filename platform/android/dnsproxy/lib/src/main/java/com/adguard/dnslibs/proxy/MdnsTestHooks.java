package com.adguard.dnslibs.proxy;

/**
 * Test-only hooks exposing the internal state of the Android mDNS integration.
 *
 * <p>Package-private and not part of the public API: the instrumentation tests in the same
 * package use them to verify that resolving a {@code .local} name holds a
 * {@code WifiManager.MulticastLock} and binds the mDNS sockets to the network handle of a
 * {@code system://<interface>} upstream. The native methods live in {@code libadguard-dns.so}.
 */
final class MdnsTestHooks {
    private MdnsTestHooks() {
    }

    /**
     * @return whether the mDNS {@code WifiManager.MulticastLock} is currently held.
     */
    static native boolean isMulticastLockHeld();

    /**
     * @return the last network handle an mDNS socket was bound to, or {@code 0} if none.
     */
    static native long getLastBoundNetworkHandle();
}
