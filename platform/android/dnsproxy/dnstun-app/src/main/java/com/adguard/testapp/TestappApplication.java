package com.adguard.testapp;

import android.app.Application;
import android.util.Log;

import com.adguard.dnslibs.proxy.DnsProxy;

public class TestappApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        DnsProxy.setLogLevel(DnsProxy.LogLevel.TRACE);
        DnsProxy.setLoggingCallback((level, message) -> {
            switch (DnsProxy.LogLevel.translate(level)) {
                case ERROR:
                    Log.e("DnsTunApp", message);
                    break;
                case WARN:
                    Log.w("DnsTunApp", message);
                    break;
                case INFO:
                    Log.i("DnsTunApp", message);
                    break;
                case DEBUG:
                    Log.d("DnsTunApp", message);
                    break;
                case TRACE:
                    Log.v("DnsTunApp", message);
                    break;
            }
        });
    }
}
