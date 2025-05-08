package org.bouncycastle.crypto.internal.modes.gcm;

import java.util.Map;
import java.util.WeakHashMap;

import org.bouncycastle.util.Arrays;

public class GCMMultiplierCache
{
    private static final Map<CacheKey, MultiplierProvider> values = new WeakHashMap<CacheKey, MultiplierProvider>();
    private static final CacheKey[] preserve = new CacheKey[8];       // keep last 8 entries.

    private static int preserveCounter = 0;

    public static GCMMultiplier fetch(byte[] H)
    {
        byte[] h = Arrays.clone(H);

        CacheKey key = new CacheKey(h);

        MultiplierProvider m;

        synchronized (values)
        {
            m = values.get(key);
            if (m == null)
            {
                m = new MultiplierProvider(h);
                values.put(key, m);
                preserve[preserveCounter] = key;
                preserveCounter = (preserveCounter + 1) % preserve.length;
            }
        }

        return m.getMultiplier();
    }

    public synchronized int size()
    {
        return values.size();
    }

    public synchronized void clear()
    {
        values.clear();
        for (int i = 0; i != preserve.length; i++)
        {
            preserve[i] = null;
        }
    }

    private static class MultiplierProvider
    {
        private final byte[] H;

        private GCMMultiplier m;

        MultiplierProvider(byte[] H)
        {
            this.H = H;
        }

        synchronized GCMMultiplier getMultiplier()
        {
            if (m == null)
            {
                m = new Tables8kGCMMultiplier();
                m.init(H);
            }

            return m;
        }
    }

    private static class CacheKey
    {
        private final byte[] H;
        private final int hashCode;

        CacheKey(byte[] H)
        {
            this.H = H;
            this.hashCode = Arrays.hashCode(H);
        }

        public int hashCode()
        {
            return hashCode;
        }

        public boolean equals(Object o)
        {
            if (o == this)
            {
                return true;
            }

            if (o instanceof CacheKey)
            {
                CacheKey other = (CacheKey)o;

                return Arrays.areEqual(other.H, this.H);
            }

            return false;
        }
    }
}
