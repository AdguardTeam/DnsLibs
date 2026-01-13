package com.adguard.testapp;

import android.os.Build;

public class TcpIpStackSettings {

    public static int MTU = 9000;

    public static boolean WRITE_PCAP = false;

    /**
     * @return true if Android version is 4.3 (not newer or older).
     */
    private static boolean isJellyBeanMr3() {
        return Build.VERSION.SDK_INT == 18;
    }

    /**
     * @return true if Android version is 4.4 (not newer or older).
     */
    private static boolean isKitKat() {
        return Build.VERSION.SDK_INT == 19;
    }

    private static int calculateMtu() {
        if (isJellyBeanMr3() || isKitKat()) {
            // Using small mtu for android 4.3
            // http://jira.performix.ru/browse/AG-7226
            // We may use larger MTU for KitKat but MSS-fix is needed
            return 1500;
        } else {
            // Using large MTU allows us to create less TCP packets
            // which is good for CPU usage
            return 9000;
        }
    }
}
