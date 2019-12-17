package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class CertificateVerificationEvent {
    /** The certificate being verified */
    private byte[] certificate;
    /** The certificate chain */
    private List<byte[]> chain = new ArrayList<>();

    public byte[] getCertificate() {
        return certificate;
    }

    public List<byte[]> getChain() {
        return chain;
    }

    private CertificateVerificationEvent() {
        // Initialized from native code
    }

    @Override
    public String toString() {
        return "CertificateVerificationEvent{" +
                "certificate=" + Arrays.toString(certificate) +
                ", chain=" + chain +
                '}';
    }
}
