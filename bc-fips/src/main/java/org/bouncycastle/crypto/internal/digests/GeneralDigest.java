/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.digests;

import org.bouncycastle.crypto.internal.ExtendedDigest;
import org.bouncycastle.util.Memoable;

/**
 * base implementation of MD4 family style digest as outlined in
 * "Handbook of Applied Cryptography", pages 344 - 347.
 */
public abstract class GeneralDigest
    implements ExtendedDigest, Memoable
{
    private static final int BYTE_LENGTH = 64;
    private byte[] xBuf;
    private int xBufOff;

    private long byteCount;

    /**
     * Standard constructor
     */
    protected GeneralDigest()
    {
        xBuf = new byte[4];
        xBufOff = 0;
    }

    /**
     * Copy constructor.  We are using copy constructors in place
     * of the Object.clone() interface as this interface is not
     * supported by J2ME.
     */
    protected GeneralDigest(GeneralDigest t)
    {
        xBuf = new byte[t.xBuf.length];

        copyIn(t);
    }

    protected void copyIn(GeneralDigest t)
    {
        System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length);

        xBufOff = t.xBufOff;
        byteCount = t.byteCount;
    }

    public void update(
        byte in)
    {
        xBuf[xBufOff++] = in;

        if (xBufOff == xBuf.length)
        {
            processWord(xBuf, 0);
            xBufOff = 0;
        }

        byteCount++;
    }

    public void update(
        byte[] in,
        int inOff,
        int len)
    {
        len = Math.max(0, len);

        //
        // fill the current word
        //
        int i = 0;
        if (xBufOff != 0)
        {
            while (i < len)
            {
                xBuf[xBufOff++] = in[inOff + i++];
                if (xBufOff == 4)
                {
                    processWord(xBuf, 0);
                    xBufOff = 0;
                    break;
                }
            }
        }

        //
        // process whole words.
        //
        int limit = ((len - i) & ~3) + i;
        for (; i < limit; i += 4)
        {
            processWord(in, inOff + i);
        }

        //
        // load in the remainder.
        //
        while (i < len)
        {
            xBuf[xBufOff++] = in[inOff + i++];
        }

        byteCount += len;
    }

    public void finish()
    {
        long bitLength = (byteCount << 3);

        //
        // add the pad bytes.
        //
        update((byte)128);

        while (xBufOff != 0)
        {
            update((byte)0);
        }

        processLength(bitLength);

        processBlock();
    }

    public void reset()
    {
        byteCount = 0;

        xBufOff = 0;
        for (int i = 0; i < xBuf.length; i++)
        {
            xBuf[i] = 0;
        }
    }

    public int getByteLength()
    {
        return BYTE_LENGTH;
    }

    protected abstract void processWord(byte[] in, int inOff);

    protected abstract void processLength(long bitLength);

    protected abstract void processBlock();

    @Override
    public String toString()
    {
        String name = this.getClass().getName();
        int p = name.lastIndexOf(".");
        if (p >= 0 && p + 1 < name.length())
        {
            name = name.substring(p + 1);
        }
        name = name.replace("Digest", "");
        return name + "[Java]()";
    }
}
