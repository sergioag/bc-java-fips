package org.bouncycastle.crypto.fips;

import java.util.concurrent.atomic.AtomicInteger;

class TestTrigger
{
    private AtomicInteger threshold = new AtomicInteger(0);

    boolean triggerTest()
    {
        // this code will result test being triggered on first use.
        if (threshold.compareAndSet(0, 1))
        {
            return true;
        }

        if (threshold.getAndIncrement() > ((System.currentTimeMillis() & 0x3ff) + 50))
        {
            threshold.set(1);
            return true;
        }

        return false;
    }
}
