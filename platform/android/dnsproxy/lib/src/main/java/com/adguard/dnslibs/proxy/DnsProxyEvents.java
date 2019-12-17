package com.adguard.dnslibs.proxy;

public interface DnsProxyEvents {
    /**
     * Raised right after a request is processed.
     * Notes:
     *  - if there are several upstreams in proxy configuration, the proxy tries each one
     *    consequently until it gets successful status, so in this case each failed upstream
     *    fires the event - i.e., several events will be raised for the request
     */
    void onRequestProcessed(DnsRequestProcessedEvent event);
}
