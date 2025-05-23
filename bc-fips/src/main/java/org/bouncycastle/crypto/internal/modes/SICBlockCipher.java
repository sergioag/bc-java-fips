/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.modes;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.SkippingStreamCipher;
import org.bouncycastle.crypto.internal.StreamBlockCipher;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implements the Segmented Integer Counter (SIC) mode on top of a simple
 * block cipher. This mode is also known as CTR mode.
 */
public class SICBlockCipher
    extends StreamBlockCipher
    implements SkippingStreamCipher
{
    private final BlockCipher cipher;
    private final int blockSize;

    private byte[] IV;
    private byte[] counter;
    private byte[] counterOut;
    private int byteCount;

    /**
     * Basic constructor.
     *
     * @param c the block cipher to be used.
     */
    public SICBlockCipher(BlockCipher c)
    {
        super(c);

        this.cipher = c;
        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[blockSize];
        this.counter = new byte[blockSize];
        this.counterOut = new byte[blockSize];
        this.byteCount = 0;
    }

    public void init(
        boolean forEncryption, //ignored by this CTR mode
        CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            this.IV = Arrays.clone(ivParam.getIV());

            int maxCounterSize = (8 > blockSize / 2) ? blockSize / 2 : 8;

            if (blockSize - IV.length > maxCounterSize)
            {
                throw new IllegalArgumentException("CTR mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");
            }

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }

            reset();
        }
        else
        {
            throw new IllegalArgumentException("CTR mode requires ParametersWithIV");
        }
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/SIC";
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        processBytes(in, inOff, blockSize, out, outOff);

        return blockSize;
    }

    protected byte calculateByte(byte in)
        throws DataLengthException, IllegalStateException
    {
        if (byteCount == 0)
        {
            checkCounter();

            cipher.processBlock(counter, 0, counterOut, 0);

            return (byte)(counterOut[byteCount++] ^ in);
        }

        byte rv = (byte)(counterOut[byteCount++] ^ in);

        if (byteCount == counter.length)
        {
            byteCount = 0;

            incrementCounter();
        }

        return rv;
    }

    private void checkCounter()
    {
        // if the IV is the same as the blocksize we assume the user know's what they are doing
        if (IV.length != blockSize)
        {
            for (int i = 0; i != IV.length; i++)
            {
                if (counter[i] != IV[i])
                {
                    throw new IllegalStateException("Counter in CTR mode out of range.");
                }
            }
        }
    }

    private void incrementCounterPow2(int pow2Div8)
    {
        // increment counter by 1 << 8 * pow2Div8
        for (int i = counter.length - (1 + pow2Div8); i >= 0 && ++counter[i] == 0; i--)
        {
            ; // do nothing - pre-increment and test for 0 in counter does the job.
        }
    }

    private void incrementCounter(int offSet)
    {
        byte old = counter[counter.length - 1];

        counter[counter.length - 1] += offSet;

        if (old != 0 && counter[counter.length - 1] < old)
        {
            incrementCounterPow2(1);
        }
    }

    private void incrementCounter()
    {
        // increment counter by 1.
        for (int i = counter.length - 1; i >= 0 && ++counter[i] == 0; i--)
        {
            ; // do nothing - pre-increment and test for 0 in counter does the job.
        }
    }

    private void decrementCounterPow2(int pow2Div8)
    {
        if (counter[pow2Div8] == 0)
        {
            boolean nonZero = false;

            for (int i = counter.length - (1 + pow2Div8); i > 0; i--)
            {
                if (counter[i] != 0)
                {
                    nonZero = true;
                }
            }

            if (!nonZero)
            {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
        }

        // decrement counter by 1.
        for (int i = counter.length - (1 + pow2Div8); i >= 0 && --counter[i] == -1; i--)
        {
            ;
        }
    }

    private void decrementCounter()
    {
        // decrement counter by 1.
        for (int i = counter.length - 1; i >= 0 && --counter[i] == -1; i--)
        {
            ;
        }
    }

    private void adjustCounter(long n)
    {
        if (n >= 0)
        {
            long numBlocks = (n + byteCount) / blockSize;

            if (numBlocks > 255)
            {
                long gap = numBlocks;

                for (int i = 5; i >= 1; i--)
                {
                    long diff = 1L << (8 * i);

                    while (gap >= diff)
                    {
                        incrementCounterPow2(i);

                        gap -= diff;
                    }
                }

                incrementCounter((int)gap);
            }
            else
            {
                incrementCounter((int)numBlocks);
            }

            byteCount = (int)((n + byteCount) - (blockSize * numBlocks));
        }
        else
        {
            long numBlocks = (-n - byteCount) / blockSize;

            if (numBlocks > 255)
            {
                long gap = numBlocks;

                for (int i = 5; i >= 1; i--)
                {
                    long diff = 1L << (8 * i);

                    while (gap > diff)
                    {
                        decrementCounterPow2(i);

                        gap -= diff;
                    }
                }

                for (long i = 0; i != gap; i++)
                {
                    decrementCounter();
                }
            }
            else
            {
                for (long i = 0; i != numBlocks; i++)
                {
                    decrementCounter();
                }
            }

            int gap = (int)(byteCount + n + (blockSize * numBlocks));

            if (gap >= 0)
            {
                byteCount = 0;
            }
            else
            {
                decrementCounter();
                byteCount = blockSize + gap;
            }
        }
    }

    public void reset()
    {
        Arrays.fill(counter, (byte)0);
        System.arraycopy(IV, 0, counter, 0, IV.length);
        cipher.reset();
        this.byteCount = 0;
    }

    public long skip(long numberOfBytes)
    {
        adjustCounter(numberOfBytes);

        checkCounter();

        cipher.processBlock(counter, 0, counterOut, 0);

        return numberOfBytes;
    }

    public long seekTo(long position)
    {
        reset();

        return skip(position);
    }

    public long getPosition()
    {
        byte[] res = new byte[counter.length];

        System.arraycopy(counter, 0, res, 0, res.length);

        for (int i = res.length - 1; i >= 1; i--)
        {
            int v;
            if (i < IV.length)
            {
                v = (res[i] & 0xff) - (IV[i] & 0xff);
            }
            else
            {
                v = (res[i] & 0xff);
            }

            if (v < 0)
            {
                res[i - 1]--;
                v += 256;
            }

            res[i] = (byte)v;
        }

        return Pack.bigEndianToLong(res, res.length - 8) * blockSize + byteCount;
    }
}
