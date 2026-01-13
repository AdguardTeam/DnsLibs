package com.adguard.testapp;

import androidx.annotation.NonNull;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

class CustomThreadFactory implements ThreadFactory {

    private final AtomicInteger nextId = new AtomicInteger(1);
    private final String prefix;

    CustomThreadFactory(String prefix) {
        this.prefix = prefix;
    }

    @Override
    public Thread newThread(@NonNull Runnable r) {
        return new Thread(r, prefix + nextId.getAndIncrement());
    }
}
