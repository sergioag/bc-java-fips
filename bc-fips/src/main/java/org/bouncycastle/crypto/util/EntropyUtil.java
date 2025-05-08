package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.OutputXOFCalculator;
import org.bouncycastle.crypto.fips.FipsEntropyConfig;
import org.bouncycastle.crypto.fips.FipsOutputXOFCalculator;
import org.bouncycastle.crypto.fips.FipsParameters;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsXOFOperatorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utility methods for making use of EntropySources.
 */
public class EntropyUtil
{
    /**
     * Generate numBytes worth of entropy from the passed in entropy source.
     *
     * @param entropySource the entropy source to request the data from.
     * @param numBytes      the number of bytes of entropy requested.
     * @return a byte array populated with the random data.
     */
    public static byte[] generateSeed(EntropySource entropySource, int numBytes)
    {
        byte[] bytes = new byte[numBytes];
        byte[] xofKey = entropySource.getEntropy();

        if (numBytes * 8 <= entropySource.entropySize())
        {
            byte[] ent = entropySource.getEntropy();

            System.arraycopy(ent, 0, bytes, 0, bytes.length);
        }
        else
        {
            int entSize = entropySource.entropySize() / 8;

            for (int i = 0; i < bytes.length; i += entSize)
            {
                byte[] ent = entropySource.getEntropy();

                if (ent.length <= bytes.length - i)
                {
                    System.arraycopy(ent, 0, bytes, i, ent.length);
                }
                else
                {
                    System.arraycopy(ent, 0, bytes, i, bytes.length - i);
                }
            }
        }

        OutputXOFCalculator calc = new FipsSHS.XOFOperatorFactory().createOutputXOFCalculator(FipsSHS.SHAKE256);

        OutputStream fOut = calc.getFunctionStream();

        try
        {
            fOut.write(xofKey);
            fOut.write(bytes);
            fOut.close();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("failure in seed generator");
        }
        finally
        {
            Arrays.clear(xofKey);
            Arrays.clear(bytes);
        }

        calc.getFunctionOutput(bytes, 0, bytes.length);

        return bytes;
    }

    /**
     * SP 800-90B, 4.4.1: Return true if the entropy source is stuck. By default this will be C calculated for alpha=20, with
     * a H value of 8. The default C value can be set using "org.bouncycastle.ent.stkC".
     *
     * @param prev    the last byte of the previous buffer.
     * @param current the current set of entropy samples.
     * @return null if there's no issue, an error message if there is.
     */
    public static String isNotStuck(byte prev, byte[] current)
    {
        int C = FipsEntropyConfig.getStuckC();

        if (current.length < C)
        {
            throw new IllegalArgumentException("alpha value too large for entropy size");
        }

        int b = 1;

        byte a = prev;
        for (int i = 0; i != current.length; i++)
        {
            byte x = current[i];
            if (x == a)
            {
                b = b + 1;
                if (b >= C)
                {
                    return "entropy source stuck";
                }
            }
            else
            {
                a = x;
                b = 1;
            }
        }

        return null;
    }

    /**
     * SP 800-90B, 4.4.2: Return true if the entropy is proportionate. By default this will be for alpha=20, with
     * a H value of 8. The C value can be set using "org.bouncycastle.ent.adptC"
     *
     * @param current the current sampling of entropy to scan.
     * @return null if there's no issue, an error message if there is.
     */
    public static String isProportionate(WindowStats stats, byte[] current)
    {
        try
        {
            for (int i = 0; i < current.length; i++)
            {
                stats.check(current[i]);
            }

            return null;
        }
        catch (IllegalStateException e)
        {
            return e.getMessage();
        }
    }

    /**
     * Create an initial stats object.
     *
     * @return a WindowStats object.
     */
    public static WindowStats createStats()
    {
        return new WindowStats(FipsEntropyConfig.getAdaptiveProportionateC(),
            FipsEntropyConfig.getAdaptiveProportionateW());
    }

    public static class WindowStats
    {
        private final int W;
        private final int adptC;

        byte a;
        int i;
        int b;

        WindowStats(int adptC, int W)
        {
            this.adptC = adptC;
            this.W = W;
            // prime for setup
            this.i = W;
        }

        void incB()
        {
            b++;
            if (b >= adptC)
            {
                throw new IllegalStateException("proportionate test failed");
            }
        }

        void check(byte sample)
        {
            if (i > (W - 1))
            {
                reset(sample);
            }
            else if (this.a == sample)
            {
                incB();
            }
            i++;
        }

        void reset(byte sample)
        {
            this.b = 1;
            this.i = 0;
            this.a = sample;
        }
    }
}
