package com.adguard.testapp;

import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import com.adguard.dnslibs.proxy.DnsProxy;
import com.adguard.dnslibs.proxy.DnsProxySettings;
import com.adguard.dnslibs.proxy.DnsTunListener;
import com.adguard.dnslibs.proxy.FilterParams;
import com.adguard.dnslibs.proxy.UpstreamSettings;

import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DnsTunVpnService extends VpnService {

    private static final String TAG = "DnsTunVpnService";
    private static volatile boolean isActive = false;
    private final Object syncRoot = new Object();
    private Thread serviceThread;

    public static final String ACTION = "action";
    public static final int START = 1;
    public static final int STOP = 2;

    private volatile static DnsTunVpnService lastVpnService = null;

    private DnsTunListener tunListener;
    private DnsProxy dnsProxy;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        int action = intent != null ? intent.getIntExtra(ACTION, 0) : START;
        switch (action) {
            case START:
                startService();
                break;
            case STOP:
                stopService();
                break;
        }
        return Service.START_NOT_STICKY;
    }

    private void stopService() {
        synchronized (syncRoot) {
            if (tunListener != null) {
                tunListener.close();
                tunListener = null;
            }
            if (dnsProxy != null) {
                dnsProxy.close();
                dnsProxy = null;
            }
            isActive = false;
        }
    }

    private void startService() {
        synchronized (syncRoot) {
            if (isActive) {
                Log.i(TAG, "VPN service is already running");
                return;
            }

            serviceThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    Thread.currentThread().setName("VPN");
                    setupVpn();
                }
            });
            serviceThread.setDaemon(true);
            serviceThread.start();
        }
    }

    @Override
    public void onRevoke() {
        stopService();
    }

    private void setupVpn() {
        if (isActive) {
            Log.w(TAG, "VPN Service is already set up");
            return;
        }
        Log.i(TAG, "Setting up VPN");

        int mtu = 1500;

        Builder builder = new Builder();
        builder.setSession("DNS TUN Listener Test");
        builder.setMtu(mtu);
        try {
            builder.addDisallowedApplication("com.adguard.testapp");
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException(e);
        }
        try {
            builder.addAddress(InetAddress.getByName("198.18.53.1"), 32);
            builder.addRoute(InetAddress.getByName("198.18.53.53"), 32);
            builder.addDnsServer(InetAddress.getByName("198.18.53.53"));
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        ParcelFileDescriptor tunFd = builder.establish();
        if (tunFd == null) {
            Log.e(TAG, "Can't start VPN");
            return;
        }

        try {
            Log.i(TAG, "Create DnsProxy");
            DnsProxySettings settings = new DnsProxySettings();

            // Configure upstream DNS server
            UpstreamSettings upstream = new UpstreamSettings();
            upstream.setAddress("94.140.14.14");  // AdGuard DNS
            upstream.setId(42);
            settings.setUpstreams(Collections.singletonList(upstream));

            // Add filtering for testing (evil.com and evil.org are blocked)
            List<FilterParams> filters = new ArrayList<>();
            
            // Hosts-style rule: 0.0.0.0 evil.com
            FilterParams filter1 = new FilterParams();
            filter1.setId(42);
            filter1.setData("0.0.0.0 evil.com\n");
            filter1.setInMemory(true);
            filters.add(filter1);
            
            // AdBlock-style rule: ||evil.org^
            FilterParams filter2 = new FilterParams();
            filter2.setId(43);
            filter2.setData("||evil.org^\n");
            filter2.setInMemory(true);
            filters.add(filter2);
            
            settings.setFilterParams(filters);
            
            // Disable cache and optimistic cache for testing
            settings.setDnsCacheSize(0);
            settings.setOptimisticCache(false);
            settings.setEnableHttp3(false);

            dnsProxy = new DnsProxy(this, settings);

            Log.i(TAG, "Create DnsTunListener");
            tunListener = new DnsTunListener(
                tunFd.detachFd(),
                mtu,
                (request, replyHandler) -> {
                    // Process DNS request asynchronously through DnsProxy
                    dnsProxy.handleMessageAsync(request, null, replyHandler::onReply);
                }
            );

            lastVpnService = this;
            isActive = true;
            Log.i(TAG, "VPN has been started");
        } catch (Exception e) {
            closeQuietly(tunFd);
            Log.e(TAG, "Exception occurred while starting VPN", e);
        }
    }

    private void closeQuietly(ParcelFileDescriptor fd) {
        try {
            fd.close();
        } catch (IOException ignored) {}
    }

    public static DnsTunVpnService getLastVpnService() {
        return lastVpnService;
    }

    public boolean isStarted() {
        return isActive;
    }
}
