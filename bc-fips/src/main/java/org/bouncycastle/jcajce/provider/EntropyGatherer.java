package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.util.Properties;

class EntropyGatherer
    implements Runnable
{
    private final int numBytes;
    private final SecureRandom baseRandom;
    private final AtomicBoolean seedAvailable;
    private final AtomicReference<byte[]> entropy;

    EntropyGatherer(int numBytes, SecureRandom baseRandom, AtomicBoolean seedAvailable, AtomicReference<byte[]> entropy)
    {
        this.numBytes = numBytes;
        this.baseRandom = baseRandom;
        this.seedAvailable = seedAvailable;
        this.entropy = entropy;
    }

    private void sleep(long ms)
    {
        try
        {
            Thread.sleep(ms);
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
    }

    public void run()
    {
        long ms;
        String pause = Properties.getPropertyValue("org.bouncycastle.drbg.gather_pause_secs");

        if (pause != null)
        {
            try
            {
                ms = Long.parseLong(pause) * 1000;
            }
            catch (Exception e)
            {
                ms = 5000;
            }
        }
        else
        {
            ms = 5000;
        }

        byte[] seed = new byte[numBytes];
        for (int i = 0; i < numBytes / 8; i++)
        {
            // we need to be mindful that we may not be the only thread/process looking for entropy
            sleep(ms);
            byte[] rn = baseRandom.generateSeed(8);
            System.arraycopy(rn, 0, seed, i * 8, rn.length);
        }

        int extra = numBytes - ((numBytes / 8) * 8);
        if (extra != 0)
        {
            sleep(ms);
            byte[] rn = baseRandom.generateSeed(extra);
            System.arraycopy(rn, 0, seed, seed.length - rn.length, rn.length);
        }

        entropy.set(seed);
        seedAvailable.set(true);
    }
}
