package com.adguard.dnslibs.proxy;

import android.content.Context;

import org.jetbrains.annotations.NotNull;
import org.slf4j.helpers.MessageFormatter;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class DnsProxy implements Closeable {

    public enum InitErrorCode {
        PROXY_NOT_SET,
        EVENT_LOOP_NOT_SET,
        INVALID_ADDRESS,
        EMPTY_PROXY,
        PROTOCOL_ERROR,
        LISTENER_INIT_ERROR,
        INVALID_IPV4,
        INVALID_IPV6,
        UPSTREAM_INIT_ERROR,
        FALLBACK_FILTER_INIT_ERROR,
        FILTER_LOAD_ERROR,
        MEM_LIMIT_REACHED,
        NON_UNIQUE_FILTER_ID,
        OK,
    }

    /**
     * Possible combination of `success` and `code` + `description`:
     * 1) if success = true and `code` == `DnsProxyInitErrorCode::OK` -> there are no error occurred
     * (`description` contains default value)
     * 2) if success = true and `code` != `DnsProxyInitErrorCode::OK` -> there are some warnings, see
     * `description`
     * 3) if success = false -> `code` and `description` contains error code and description for error
     */
    static class InitResult {
        public boolean success;
        public InitErrorCode code = InitErrorCode.OK;
        public String description = "";
    }

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
     *
     * @param context  app context.
     * @param settings the settings. Not {@code null}.
     * @throws NullPointerException  if any of the arguments is {@code null}.
     * @throws DnsProxyInitException If the proxy fails to initialize.
     */
    public DnsProxy(@NotNull Context context, @NotNull DnsProxySettings settings)
            throws DnsProxyInitException, NullPointerException {
        this(context, settings, null);
    }

    /**
     * Initializes the DNS proxy.
     *
     * @param context  app context.
     * @param settings the settings. Not {@code null}.
     * @param events   the event callback. May be {@code null}.
     * @throws NullPointerException  if any of the required arguments is {@code null}.
     * @throws DnsProxyInitException If the proxy fails to initialize.
     */
    public DnsProxy(@NotNull Context context, @NotNull DnsProxySettings settings, DnsProxyEvents events)
            throws DnsProxyInitException, NullPointerException {
        this();
        Objects.requireNonNull(settings);
        if (settings.isDetectSearchDomains()) {
            List<String> searchDomains = DnsNetworkUtils.getDNSSearchDomains(context);
            if (searchDomains != null) {
                for (String domain : searchDomains) {
                    if (domain.startsWith(".")) {
                        domain = domain.substring(1);
                    }
                    if (domain.endsWith(".")) {
                        domain = domain.substring(0, domain.length() - 1);
                    }
                    if (!domain.isEmpty()) {
                        settings.getFallbackDomains().add(String.format("*.%s", domain));
                    }
                }
            }
        }
        InitResult result = init(nativePtr, settings, new EventsAdapter(events));
        if (!result.success) {
            close();
            throw new DnsProxyInitException(result);
        }
        state = State.INITIALIZED;
    }

    /**
     * Handles a DNS message.
     * <p>
     * It is safe to call this method from different threads once the proxy has been initialized
     * and properly shared. Other methods of this class are NOT thread-safe.
     *
     * @param message a message from client.
     * @param info    additional information about the message or how to process it.
     * @return a blocked DNS message if the message was blocked,
     * a DNS resolver response if the message passed,
     * an empty array in case of an error.
     * @throws IllegalStateException if the proxy is closed.
     */
    public byte[] handleMessage(byte[] message, DnsMessageInfo info) throws IllegalStateException {
        if (state != State.INITIALIZED) {
            throw new IllegalStateException("Closed");
        }
        return handleMessage(nativePtr, message, info);
    }

    /**
     * Same as {@link #handleMessage(byte[], DnsMessageInfo)}, but the result is communicated
     * asynchronously by invoking `callback` on an unspecified thread.
     */
    public void handleMessageAsync(byte[] message, DnsMessageInfo info, Consumer<byte[]> callback) {
        if (state != State.INITIALIZED) {
            throw new IllegalStateException("Closed");
        }
        handleMessageAsync(nativePtr, message, info, callback);
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

    private native InitResult init(long nativePtr, DnsProxySettings settings, EventsAdapter events);

    private native void deinit(long nativePtr);

    private native void delete(long nativePtr);

    private native byte[] handleMessage(long nativePtr, byte[] message, DnsMessageInfo info);

    private native void handleMessageAsync(long nativePtr, byte[] message, DnsMessageInfo info, Consumer<byte[]> callback);

    public enum LogLevel {
        ERROR, WARN, INFO, DEBUG, TRACE;

        static LogLevel translate(int nativeLogLevel) {
            if (nativeLogLevel < 0 || nativeLogLevel >= values().length) {
                throw new IllegalArgumentException("nativeLogLevel out of range");
            }
            return values()[nativeLogLevel];
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
     *
     * @param str string to check
     * @return true if string is a valid rule, false otherwise
     */
    public static native boolean isValidRule(String str);

    /**
     * Return the DNS proxy library version.
     */
    public static native String version();

    /**
     * Checks if upstream is valid and available
     *
     * @param upstreamSettings Upstream settings
     * @param timeoutMs        Maximum amount of time, in milliseconds, allowed for upstream exchange
     * @param ipv6Available    Whether IPv6 is available (bootstrapper is allowed to make AAAA queries)
     * @param offline          Don't perform online upstream check
     * @throws IllegalArgumentException with an explanation if check failed
     */
    public static void testUpstream(UpstreamSettings upstreamSettings,
                                    long timeoutMs, boolean ipv6Available, boolean offline)
            throws IllegalArgumentException {
        String error;
        try (final DnsProxy proxy = new DnsProxy()) {
            error = testUpstreamNative(proxy.nativePtr, upstreamSettings, timeoutMs, ipv6Available,
                    new EventsAdapter(null), offline);
        }
        if (error != null) {
            throw new IllegalArgumentException(error);
        }
    }

    private static native String testUpstreamNative(long nativePtr, Object upstreamSettings, long timeoutMs,
                                                    boolean ipv6, Object eventsAdapter, boolean offline);

    /**
     * Events adapter implementation.
     * Callbacks from this class are called from native code.
     * This class is private. See {@link DnsProxyEvents} for user events interface.
     */
    private static class EventsAdapter {
        private static final Logger log = DnsProxy.getLogger(EventsAdapter.class);

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

    /**
     * Suggest an action based on a filtering log event.
     *
     * @throws NullPointerException if any argument is {@code null}.
     */
    public FilteringLogAction filteringLogActionFromEvent(@NotNull DnsRequestProcessedEvent event) {
        return filteringLogActionFromEvent(nativePtr, Objects.requireNonNull(event));
    }

    private native FilteringLogAction filteringLogActionFromEvent(long nativePtr, DnsRequestProcessedEvent event);

    /**
     * Generate a rule from a template and a corresponding event.
     *
     * @return A rule or {@code null} on error.
     * @throws NullPointerException if any argument is {@code null}.
     */
    public String generateRuleWithOptions(@NotNull FilteringLogAction.RuleTemplate template,
                                          @NotNull DnsRequestProcessedEvent event,
                                          @NotNull EnumSet<FilteringLogAction.Option> options) {
        int opt = 0;
        for (FilteringLogAction.Option option : options) {
            opt |= option.value;
        }
        return generateRuleFromTemplate(nativePtr, Objects.requireNonNull(template), Objects.requireNonNull(event), opt);
    }

    private native String generateRuleFromTemplate(long nativePtr, FilteringLogAction.RuleTemplate template, DnsRequestProcessedEvent event, int options);

    @FunctionalInterface
    public interface LoggingCallback {
        /**
         * Write a message to the log. Use {@link LogLevel#translate(int)}
         * to translate the log level.
         */
        void log(int level, String message);
    }

    public static native void setLoggingCallback(LoggingCallback callback);

    interface Logger {
        default void error(String message, Throwable t) {
            log(LogLevel.ERROR, message + ": {}", t);
        }

        default void warn(String message, Throwable t) {
            log(LogLevel.WARN, message + ": {}", t);
        }

        default void info(String message, Throwable t) {
            log(LogLevel.INFO, message + ": {}", t);
        }

        default void debug(String message, Throwable t) {
            log(LogLevel.DEBUG, message + ": {}", t);
        }

        default void trace(String message, Throwable t) {
            log(LogLevel.TRACE, message + ": {}", t);
        }

        default void error(String format, Object... args) {
            log(LogLevel.ERROR, format, args);
        }

        default void warn(String format, Object... args) {
            log(LogLevel.WARN, format, args);
        }

        default void info(String format, Object... args) {
            log(LogLevel.INFO, format, args);
        }

        default void debug(String format, Object... args) {
            log(LogLevel.DEBUG, format, args);
        }

        default void trace(String format, Object... args) {
            log(LogLevel.TRACE, format, args);
        }

        void log(LogLevel level, String format, Object... args);
    }

    static Logger getLogger(Class<?> type) {
        return (level, format, args) -> log(level.ordinal(),
                type.getSimpleName() + MessageFormatter.arrayFormat(format, args).getMessage());
    }

    private static native void log(int level, String message);
}
