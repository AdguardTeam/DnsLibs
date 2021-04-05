package com.adguard.dnslibs.proxy;

import android.content.Context;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class DnsProxy implements Closeable {
    private static final Logger log = LoggerFactory.getLogger(DnsProxy.class);

    private enum State {
        NEW, INITIALIZED, CLOSED,
    }

    static {
        load();
    }

    private static final String LIBNAME = "adguard-dns";

    private static void load() {
        System.loadLibrary(LIBNAME);
    }

    private final long nativePtr;

    private State state = State.NEW;

    private DnsProxy() {
        nativePtr = create();
    }

    /**
     * Initializes the DNS proxy.
     * @param context app context.
     * @param settings the settings. Not {@code null}.
     * @throws NullPointerException if {@code settings == null}.
     * @throws RuntimeException     if the proxy could not initialize.
     */
    public DnsProxy(Context context, DnsProxySettings settings) {
        this(context, settings, null);
    }

    /**
     * Initializes the DNS proxy.
     * @param context  app context.
     * @param settings the settings. Not {@code null}.
     * @param events   the event callback. May be {@code null}.
     * @throws NullPointerException if {@code settings == null}.
     * @throws RuntimeException     if the proxy could not initialize.
     */
    public DnsProxy(Context context, DnsProxySettings settings, DnsProxyEvents events) throws RuntimeException {
        this();
        try {
            if (settings == null) {
                throw new NullPointerException("settings");
            }

            if (settings.isHandleDNSSuffixes()) {
                List<String> systemDnsSuffixes = DnsNetworkUtils.getSystemDnsSuffixes(context);
                if (systemDnsSuffixes != null) {
                    settings.getUserDNSSuffixes().addAll(systemDnsSuffixes);
                }
            }

            if (!init(nativePtr, settings, new EventsAdapter(events))) {
                throw new RuntimeException("Failed to initialize the native proxy, see log for details.");
            }
            state = State.INITIALIZED;
        } catch (RuntimeException e) {
            close();
            throw e;
        }
    }

    /**
     * Handles a DNS message.
     * <p>
     * It is safe to call this method from different threads once the proxy has been initialized
     * and properly shared. Other methods of this class are NOT thread-safe.
     * @param message a message from client.
     * @return a blocked DNS message if the message was blocked,
     * a DNS resolver response if the message passed,
     * an empty array in case of an error.
     * @throws IllegalStateException if the proxy is closed.
     */
    public byte[] handleMessage(byte[] message) throws IllegalStateException {
        if (state != State.INITIALIZED) {
            throw new IllegalStateException("Closed");
        }
        return handleMessage(nativePtr, message);
    }

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
    }

    /**
     * @return the default DNS proxy settings.
     */
    static DnsProxySettings getDefaultSettings() {
        try (final DnsProxy proxy = new DnsProxy()) {
            return proxy.getDefaultSettings(proxy.nativePtr);
        }
    }

    /**
     * @return the effective proxy settings.
     * @throws IllegalStateException if the proxy is closed.
     */
    public DnsProxySettings getSettings() throws IllegalStateException {
        if (state != State.INITIALIZED) {
            throw new IllegalStateException("Closed");
        }
        return getSettings(nativePtr);
    }

    private native DnsProxySettings getDefaultSettings(long nativePtr);

    private native DnsProxySettings getSettings(long nativePtr);

    private native long create();

    private native boolean init(long nativePtr, DnsProxySettings settings, EventsAdapter events);

    private native void deinit(long nativePtr);

    private native void delete(long nativePtr);

    private native byte[] handleMessage(long nativePtr, byte[] message);

    @SuppressWarnings("unused") // Called from native code
    private static void log(int level, String message) {
        switch (LogLevel.translate(level)) {
        case TRACE:
            log.trace(message);
            break;
        case DEBUG:
            log.debug(message);
            break;
        case INFO:
            log.info(message);
            break;
        case WARN:
            log.warn(message);
            break;
        case ERROR:
            log.error(message);
            break;
        }
    }

    public enum LogLevel {
        TRACE, DEBUG, INFO, WARN, ERROR; // Do NOT change the order

        //#define SPDLOG_LEVEL_TRACE 0
        //#define SPDLOG_LEVEL_DEBUG 1
        //#define SPDLOG_LEVEL_INFO 2
        //#define SPDLOG_LEVEL_WARN 3
        //#define SPDLOG_LEVEL_ERROR 4
        //#define SPDLOG_LEVEL_CRITICAL 5
        //#define SPDLOG_LEVEL_OFF 6

        private static LogLevel[] map = new LogLevel[]{
                TRACE, DEBUG, INFO, WARN, ERROR, ERROR, // map CRITICAL to ERROR
        };

        static LogLevel translate(int spdLogLevel) {
            if (spdLogLevel < 0 || spdLogLevel >= map.length) {
                return TRACE;
            }
            return map[spdLogLevel];
        }
    }

    /**
     * Only has an effect on the instances of DnsProxy created after the call to this method.
     */
    public static void setLogLevel(LogLevel level) {
        setLogLevel(level.ordinal());
    }

    private static native void setLogLevel(int level);

    /**
     * Check if string is a valid rule
     * @param str string to check
     * @return true if string is a valid rule, false otherwise
     */
    public static native boolean isValidRule(String str);

    /** Return the DNS proxy library version. */
    public static native String version();

    /**
     * Parses a DNS stamp string and returns a instance of DNS stamp or throws on error
     * @param stampStr DNS stamp string
     * @throws IllegalArgumentException with explanation
     * @return stamp instance
     */
    public static DnsStamp parseDnsStamp(String stampStr) throws IllegalArgumentException {
        Objects.requireNonNull(stampStr, "stampStr");
        Object object;
        try (final DnsProxy proxy = new DnsProxy()) {
            object = parseDnsStampNative(proxy.nativePtr, stampStr);
        }
        if (object instanceof String) {
            throw new IllegalArgumentException((String) object);
        }
        return (DnsStamp) object;
    }

    private static native Object parseDnsStampNative(long nativePtr, String stampStr);

    /**
     * Checks if upstream is valid and available
     * @param upstreamSettings Upstream settings
     * @throws IllegalArgumentException with an explanation if check failed
     */
    public static void testUpstream(UpstreamSettings upstreamSettings) throws IllegalArgumentException {
        String error;
        try (final DnsProxy proxy = new DnsProxy()) {
            error = testUpstreamNative(proxy.nativePtr, upstreamSettings, new EventsAdapter(null));
        }
        if (error != null) {
            throw new IllegalArgumentException(error);
        }
    }

    private static native String testUpstreamNative(long nativePtr, Object upstreamSettings, Object eventsAdapter);

    /**
     * Events adapter implementatoin.
     * Callbacks from this class are called from native code.
     * This class is private. See {@link DnsProxyEvents} for user events interface.
     */
    private static class EventsAdapter {
        private static final Logger log = LoggerFactory.getLogger(EventsAdapter.class);

        private final DnsProxyEvents userEvents;
        private final X509TrustManager trustManager;
        private final CertificateFactory certificateFactory;

        EventsAdapter(DnsProxyEvents userEvents) {
            this.userEvents = userEvents;
            try {
                certificateFactory = CertificateFactory.getInstance("X.509");
                final KeyStore ks = KeyStore.getInstance("AndroidCAStore");
                ks.load(null);
                final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ks);
                trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize X509 stuff", e);
            }
        }

        private static void logHandlerException(Exception e) {
            log.error("Unexpected exception in event handler: ", e);
        }

        public void onRequestProcessed(DnsRequestProcessedEvent event) {
            try {
                if (userEvents != null) {
                    userEvents.onRequestProcessed(event);
                }
            } catch (Exception e) {
                logHandlerException(e);
            }
        }

        public String onCertificateVerification(CertificateVerificationEvent event) {
            try {
                final List<X509Certificate> chain = new ArrayList<>();

                chain.add((X509Certificate) certificateFactory.generateCertificate(
                        new ByteArrayInputStream(event.getCertificate())));

                for (final byte[] cert : event.getChain()) {
                    chain.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert)));
                }

                final long startTime = System.currentTimeMillis();
                trustManager.checkServerTrusted(chain.toArray(new X509Certificate[]{}), "UNKNOWN");
                final long finishTime = System.currentTimeMillis();
                log.debug("Certificate verification took {}ms", finishTime - startTime);

                return null; // Success
            } catch (Exception e) {
                return e.toString(); // Failure
            }
        }
    }
}
