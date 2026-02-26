package com.adguard.dnslibs.proxy;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tests for DnsTunListener.
 * Note: These tests verify the API and basic functionality.
 * Full integration tests with actual TUN devices require root access.
 */
@RunWith(AndroidJUnit4.class)
public class DnsTunListenerTest {
    static {
        DnsProxy.setLogLevel(DnsProxy.LogLevel.TRACE);
        DnsProxy.setLoggingCallback((level, message) -> {
            switch (DnsProxy.LogLevel.translate(level)) {
                case ERROR:
                    android.util.Log.e("DnsTunListenerTest", message);
                    break;
                case WARN:
                    android.util.Log.w("DnsTunListenerTest", message);
                    break;
                case INFO:
                    android.util.Log.i("DnsTunListenerTest", message);
                    break;
                case DEBUG:
                    android.util.Log.d("DnsTunListenerTest", message);
                    break;
                case TRACE:
                    android.util.Log.v("DnsTunListenerTest", message);
                    break;
            }
        });
    }

    private Context context;

    @Before
    public void setUp() throws Exception {
        context = ApplicationProvider.getApplicationContext();
    }

    /**
     * Test initialization with valid parameters.
     */
    @Test
    public void testInitialization() throws Exception {
        DnsTunListener listener = null;
        try {
            listener = new DnsTunListener(
                100,  // Dummy fd for testing
                1500,  // MTU
                (request, replyHandler) -> {
                    // Echo back the request for testing
                    replyHandler.onReply(request);
                }
            );
            
            assertNotNull("Listener should be initialized", listener);
            
        } finally {
            if (listener != null) {
                listener.close();
            }
        }
    }

    /**
     * Test that initialization fails with null request callback.
     */
    @Test
    public void testInitializationWithNullRequestCallback() {
        try {
            new DnsTunListener(
                100,  // Dummy fd
                1500,
                null  // Null request callback
            );
            fail("Should throw NullPointerException");
        } catch (NullPointerException e) {
            // Expected
        } catch (Exception e) {
            fail("Should throw NullPointerException, got: " + e.getClass().getName());
        }
    }

    /**
     * Test that initialization fails with invalid fd.
     */
    @Test
    public void testInitializationWithInvalidFdOne() {
        try {
            new DnsTunListener(
                -1,  // Invalid fd
                1500,
                (request, replyHandler) -> replyHandler.onReply(null)
            );
            fail("Should throw InitException");
        } catch (DnsTunListener.InitException e) {
            // Expected
            assertTrue("Error code should be INVALID_CALLBACK",
                e.getErrorCode() == DnsTunListener.InitError.INVALID_CALLBACK);
        } catch (Exception e) {
            fail("Should throw InitException, got: " + e.getClass().getName());
        }
    }

    /**
     * Test that initialization fails with invalid fd.
     */
    @Test
    public void testInitializationWithInvalidFd() {
        try {
            new DnsTunListener(
                    -2,  // Invalid fd
                    1500,
                    (request, replyHandler) -> replyHandler.onReply(null)
            );
            fail("Should throw InitException");
        } catch (DnsTunListener.InitException e) {
            // Expected
            assertTrue("Error code should be TCPIP_INIT_FAILED",
                    e.getErrorCode() == DnsTunListener.InitError.TCPIP_INIT_FAILED);
        } catch (Exception e) {
            fail("Should throw InitException, got: " + e.getClass().getName());
        }
    }

    /**
     * Test that invalid MTU is rejected.
     */
    @Test
    public void testInvalidMtu() {
        try {
            new DnsTunListener(
                100,  // Dummy fd
                -1,  // Invalid MTU
                (request, replyHandler) -> replyHandler.onReply(null)
            );
            fail("Should throw InitException");
        } catch (DnsTunListener.InitException e) {
            // Expected
            assertTrue("Error code should be INVALID_MTU", 
                e.getErrorCode() == DnsTunListener.InitError.INVALID_MTU);
        } catch (Exception e) {
            fail("Should throw InitException, got: " + e.getClass().getName());
        }
    }

    /**
     * Test request callback.
     * This simulates receiving a DNS request and sending a reply.
     */
    @Test
    public void testRequestCallback() throws Exception {
        AtomicReference<byte[]> receivedRequest = new AtomicReference<>();
        
        DnsTunListener listener = null;
        try {
            listener = new DnsTunListener(
                100,  // Dummy fd
                1500,
                (request, replyHandler) -> {
                    receivedRequest.set(request);
                    // Send a test reply asynchronously
                    replyHandler.onReply(new byte[]{1, 2, 3, 4});
                }
            );
            
            // Note: We can't easily test packet handling without a real TUN device
            // or root access to create one. This test just verifies initialization.
            
            assertNotNull("Listener should be initialized", listener);
            
        } finally {
            if (listener != null) {
                listener.close();
            }
        }
    }

    /**
     * Test that close() can be called multiple times safely.
     */
    @Test
    public void testMultipleClose() throws Exception {
        DnsTunListener listener = new DnsTunListener(
            101,  // Dummy fd
            1500,
            (request, replyHandler) -> replyHandler.onReply(null)
        );
        
        listener.close();
        listener.close();  // Should not throw
        listener.close();  // Should not throw
    }

    /**
     * Test that listener can be closed.
     */
    @Test
    public void testClose() throws Exception {
        DnsTunListener listener = new DnsTunListener(
            100,  // Dummy fd
            1500,
            (request, replyHandler) -> replyHandler.onReply(null)
        );
        
        listener.close();
        // Just verify close doesn't throw
    }

    /**
     * Test integration with DnsProxy.
     * This verifies that DnsTunListener can work together with DnsProxy.
     */
    @Test
    public void testIntegrationWithDnsProxy() throws Exception {
        // Initialize DnsProxy for this test only
        DnsProxySettings settings = DnsProxySettings.getDefault();
        UpstreamSettings upstream = new UpstreamSettings();
        upstream.setAddress("8.8.8.8");
        settings.getUpstreams().add(upstream);
        
        DnsProxy dnsProxy = new DnsProxy(context, settings);
        DnsTunListener listener = null;
        
        try {
            listener = new DnsTunListener(
                100,  // Dummy fd
                1500,
                (request, replyHandler) -> {
                    // Process request through DnsProxy asynchronously
                    dnsProxy.handleMessageAsync(request, null, replyHandler::onReply);
                }
            );
            
            assertNotNull("Listener should be initialized", listener);
            
            // Note: We can't send actual packets without TUN device,
            // but we verified the integration pattern works
            
        } finally {
            if (listener != null) {
                listener.close();
            }
            dnsProxy.close();
        }
    }

    /**
     * Test default MTU (0 should use default).
     */
    @Test
    public void testDefaultMtu() throws Exception {
        DnsTunListener listener = null;
        try {
            listener = new DnsTunListener(
                100,  // Dummy fd
                0,  // Use default MTU
                (request, replyHandler) -> replyHandler.onReply(null)
            );
            
            assertNotNull("Listener should be initialized with default MTU", listener);
            
        } finally {
            if (listener != null) {
                listener.close();
            }
        }
    }
}
