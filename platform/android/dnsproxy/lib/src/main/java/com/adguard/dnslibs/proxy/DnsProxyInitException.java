package com.adguard.dnslibs.proxy;

public class DnsProxyInitException extends RuntimeException {
    private final DnsProxy.InitErrorCode code;

    public DnsProxyInitException(DnsProxy.InitResult result) {
        super(result.description);
        this.code = result.code;
    }

    public DnsProxy.InitErrorCode getCode() {
        return code;
    }
}
