package org.bouncycastle.crypto.general;

import java.util.logging.Logger;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.fips.FipsEntropyConfig;
import org.bouncycastle.crypto.fips.FipsOperationError;
import org.bouncycastle.crypto.util.EntropyUtil;
import org.bouncycastle.util.Arrays;

class ContinuousTestingEntropySource
    implements EntropySource
{
    private static final Logger LOG = Logger.getLogger(ContinuousTestingEntropySource.class.getName());

    private final EntropySource entropySource;

    private byte[] buf;

    private EntropyUtil.WindowStats windStats;

    public ContinuousTestingEntropySource(EntropySource entropySource)
    {
        this.entropySource = entropySource;
    }

    public boolean isPredictionResistant()
    {
        return entropySource.isPredictionResistant();
    }

    public byte[] getEntropy()
    {
        synchronized (this)
        {
            byte[] nxt;

            if (buf == null)
            {
                buf = entropySource.getEntropy();
                windStats = EntropyUtil.createStats();
                String msg = EntropyUtil.isProportionate(windStats, buf);
                if (msg != null)
                {
                    throw new IllegalStateException(msg);
                }
            }

            int retries = 0;
            int maxRetries = FipsEntropyConfig.getMaxRetries();
            String msg;

            do
            {
                retries++;
                nxt = entropySource.getEntropy();

                msg = EntropyUtil.isNotStuck(buf[buf.length - 1], nxt);
                if (msg != null)
                {
                    LOG.warning(msg);
                }

                msg = EntropyUtil.isProportionate(windStats, nxt);
                if (msg != null)
                {
                    LOG.warning(msg);
                }

                if (Arrays.areEqual(nxt, buf))
                {
                    msg = "Duplicate block detected in EntropySource output";
                    LOG.warning(msg);
                }
            }
            while (msg != null && retries <= maxRetries);

            if (retries > maxRetries)
            {
                // the entropy source is in trouble, everything is about to crash anyway.
                FipsOperationError.flag(msg);
            }

            System.arraycopy(nxt, 0, buf, 0, buf.length);

            return nxt;
        }
    }

    public int entropySize()
    {
        return entropySource.entropySize();
    }
}
