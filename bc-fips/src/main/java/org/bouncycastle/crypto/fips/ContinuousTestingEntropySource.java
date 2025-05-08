package org.bouncycastle.crypto.fips;

import java.util.logging.Logger;

import org.bouncycastle.crypto.EntropySource;
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
                // FSM_STATE:5.1, "CONTINUOUS NDRBG TEST", "The module is performing Continuous NDRNG self-test"
                // FSM_TRANS:5.1, "CONDITIONAL TEST", "CONTINUOUS NDRNG TEST", "Invoke Continuous NDRNG test"
                String msg = EntropyUtil.isProportionate(windStats, buf);
                if (msg != null)
                {
                    // FSM_TRANS:5.3, "CONTINUOUS NDRNG TEST", "SOFT ERROR", "Continuous NDRNG test failed"
                    FipsStatus.moveToErrorStatus(msg);
                }
                // FSM_TRANS:5.2, "CONTINUOUS NDRNG TEST", "CONDITIONAL TEST", "Continuous NDRNG test successful"
            }

            // FSM_STATE:5.1, "CONTINUOUS NDRBG TEST", "The module is performing Continuous NDRNG self-test"
            // FSM_TRANS:5.1, "CONDITIONAL TEST", "CONTINUOUS NDRNG TEST", "Invoke Continuous NDRNG test"
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
                // FSM_TRANS:5.3, "CONTINUOUS NDRNG TEST", "SOFT ERROR", "Continuous NDRNG test failed"
                FipsStatus.moveToErrorStatus(msg);
            }

            // FSM_TRANS:5.2, "CONTINUOUS NDRNG TEST", "CONDITIONAL TEST", "Continuous NDRNG test successful"

            System.arraycopy(nxt, 0, buf, 0, buf.length);

            return nxt;
        }
    }

    public int entropySize()
    {
        return entropySource.entropySize();
    }
}
