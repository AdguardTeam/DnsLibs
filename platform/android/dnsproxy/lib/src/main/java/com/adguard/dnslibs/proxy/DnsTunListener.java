package com.adguard.dnslibs.proxy;

import android.os.ParcelFileDescriptor;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.Closeable;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * TUN listener that handles both UDP and TCP DNS traffic from a TUN device.
 * <p>
 * This class wraps the C++ TunListener and provides a Java interface
 * for processing DNS queries from a TUN/TAP network interface.
 * <p>
 * Example usage (Android VPN service with ParcelFileDescriptor):
 * <pre>{@code
 * ParcelFileDescriptor tunFd = builder.establish();
 * DnsTunListener listener = new DnsTunListener(
 *     tunFd.getFd(),
 *     1500,
 *     (request) -> dnsProxy.handleMessage(request, null)
 * );
 * }</pre>
 */
public class DnsTunListener implements Closeable {

    /**
     * Callback for incoming DNS requests from TUN interface.
     * This callback is called for both UDP and TCP DNS traffic.
     * The callback must return the DNS response synchronously.
     */
    @FunctionalInterface
    public interface RequestCallback {
        /**
         * Process a DNS request and return the response.
         * @param request DNS request (query) without transport headers
         * @return DNS response message, or null if no response should be sent
         */
        @Nullable
        byte[] onRequest(@NotNull byte[] request);
    }

    /**
     * Initialization error codes.
     */
    public enum InitError {
        INVALID_FD,           // Invalid file descriptor
        INVALID_MTU,          // Invalid MTU value
        INVALID_CALLBACK,     // Invalid callback
        TCPIP_INIT_FAILED,    // Failed to initialize tcpip stack
    }

    /**
     * Result of initialization.
     * Contains error message if initialization failed, null otherwise.
     */
    static class InitResult {
        public String error = null;
    }

    /**
     * Exception thrown when initialization fails.
     */
    public static class InitException extends Exception {
        private final InitError errorCode;

        public InitException(InitError errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
        }

        public InitError getErrorCode() {
            return errorCode;
        }
    }

    private enum State {
        NEW, INITIALIZED, CLOSED,
    }

    static {
        // Uses the same native library as DnsProxy
        System.loadLibrary("adguard-dns");
    }

    private final long nativePtr;
    private State state = State.NEW;
    private RequestCallback requestCallback;

    /**
     * Initialize TUN listener with file descriptor.
     *
     * @param fd File descriptor of TUN device
     * @param mtu Maximum Transmission Unit size (use 0 for default 1500)
     * @param requestCallback Callback for processing DNS requests
     * @throws NullPointerException if requestCallback is null
     * @throws InitException if initialization fails
     */
    public DnsTunListener(int fd, int mtu, @NotNull RequestCallback requestCallback)
            throws InitException, NullPointerException {
        Objects.requireNonNull(requestCallback);
        this.requestCallback = requestCallback;
        this.nativePtr = create();
        
        InitResult result = init(nativePtr, fd, mtu, requestCallback);
        if (result.error != null) {
            delete(nativePtr);
            throw parseInitError(result.error);
        }
        
        state = State.INITIALIZED;
    }

    /**
     * Stop the listener and clean up resources.
     * After calling this method, the listener cannot be reused.
     */
    @Override
    public void close() {
        if (state == State.INITIALIZED) {
            deinit(nativePtr);
            state = State.NEW;
        }
        if (state == State.NEW) {
            delete(nativePtr);
            state = State.CLOSED;
        }
        requestCallback = null;
    }

    /**
     * Called from native code when a DNS request is received.
     * Must return the DNS response synchronously.
     * @param request DNS request data
     * @return DNS response, or null if no response
     */
    private byte[] onRequest(byte[] request) {
        if (requestCallback != null) {
            return requestCallback.onRequest(request);
        }
        return null;
    }

    private static InitException parseInitError(String error) {
        if (error.contains("Invalid file descriptor")) {
            return new InitException(InitError.INVALID_FD, error);
        } else if (error.contains("Invalid MTU")) {
            return new InitException(InitError.INVALID_MTU, error);
        } else if (error.contains("Callback is null")) {
            return new InitException(InitError.INVALID_CALLBACK, error);
        } else if (error.contains("Failed to initialize tcpip stack")) {
            return new InitException(InitError.TCPIP_INIT_FAILED, error);
        } else {
            return new InitException(InitError.TCPIP_INIT_FAILED, error);
        }
    }

    // Native methods
    private native long create();
    private native InitResult init(long nativePtr, int fd, int mtu, RequestCallback requestCallback);
    private native void deinit(long nativePtr);
    private native void delete(long nativePtr);
}
