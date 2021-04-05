package com.adguard.dnslibs.proxy;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Build;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static android.content.Context.CONNECTIVITY_SERVICE;

public class DnsNetworkUtils {
    /**
     * Get system DNS suffixes.
     * @param context app context.
     * @return List of strings with system dns suffixes.
     */
    static List<String> getSystemDnsSuffixes(Context context) {
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            return null;
        }

        List<String> ret = new ArrayList<>();
        Network[] networks = connectivityManager.getAllNetworks();
        for (Network activeNetwork : networks) {
            if (activeNetwork == null) {
                continue;
            }

            LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
            if (linkProperties == null) {
                continue;
            }

            String dnsSuffixes = linkProperties.getDomains();
            if (dnsSuffixes == null) {
                continue;
            }

            String[] suffixes = dnsSuffixes.split(",");
            for (String suffix : suffixes) {
                if (suffix.length() > 1) {
                    ret.add(suffix);
                }
            }
        }

        return ret;
    }
}