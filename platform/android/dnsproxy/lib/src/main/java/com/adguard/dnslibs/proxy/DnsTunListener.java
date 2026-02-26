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
 *     (request, replyHandler) -> {
 *         // Process request asynchronously
 *         dnsProxy.handleMessageAsync(request, null, replyHandler::onReply);
 *     }
 * );
 * }</pre>
 */
public class DnsTunListener implements Closeable {

    /**
     * Handler for sending DNS response back to TUN interface.
     * This handler may be called asynchronously on any thread.
     */
    @FunctionalInterface
    public interface ReplyHandler {
        /**
         * Send DNS response back to the TUN interface.
         * @param reply DNS response message, or null if no response should be sent
         */
        void onReply(@Nullable byte[] reply);
    }

    /**
     * Callback for incoming DNS requests from TUN interface.
     * This callback is called for both UDP and TCP DNS traffic.
     * The callback may process the request asynchronously and call replyHandler at any time,
     * on any thread. The request data is copied and remains valid after the callback returns.
     */
    @FunctionalInterface
    public interface RequestCallback {
        /**
         * Process a DNS request asynchronously.
         * @param request DNS request (query) without transport headers
         * @param replyHandler Handler to send the response back. May be called asynchronously.
         */
        void onRequest(@NotNull byte[] request, @NotNull ReplyHandler replyHandler);
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
     * Internal ReplyHandler implementation that bridges JNI to Java callback.
     * Created by native code and passed to user's RequestCallback.
     */
    private static class NativeReplyHandler implements ReplyHandler {
        private final long nativePtr;
        private final long completionId;
        private volatile boolean replied = false;
        
        NativeReplyHandler(long nativePtr, long completionId) {
            this.nativePtr = nativePtr;
            this.completionId = completionId;
        }
        
        @Override
        public void onReply(@Nullable byte[] reply) {
            // Ensure reply is only sent once
            if (!replied) {
                synchronized (this) {
                    if (!replied) {
                        replied = true;
                        nativeSendReply(nativePtr, completionId, reply);
                    }
                }
            }
        }
        
        private static native void nativeSendReply(long nativePtr, long completionId, byte[] reply);
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
