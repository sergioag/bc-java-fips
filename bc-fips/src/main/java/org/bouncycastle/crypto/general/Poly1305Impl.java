package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.OutputLengthException;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

/**
 * Poly1305 message authentication code, designed by D. J. Bernstein.
 * <p>
 * Poly1305 computes a 128-bit (16 bytes) authenticator, using a 128 bit nonce and a 256 bit key
 * consisting of a 128 bit key applied to an underlying cipher, and a 128 bit key (with 106
 * effective key bits) used in the authenticator.
 * <p>
 * The polynomial calculation in this implementation is adapted from the public domain <a
 * href="https://github.com/floodyberry/poly1305-donna">poly1305-donna-unrolled</a> C implementation
 * by Andrew M (@floodyberry).
 *
 * @see Poly1305KeyGenerator
 */
class Poly1305Impl
    implements Mac
{
    private static final int BLOCK_SIZE = 16;

    private final BlockCipher cipher;

    private final byte[] singleByte = new byte[1];

    // Initialised state

    /**
     * Polynomial key
     */
    private int r0, r1, r2, r3, r4;

    /**
     * Precomputed 5 * r[1..4]
     */
    private int s1, s2, s3, s4;

    /**
     * Encrypted nonce
     */
    private int k0, k1, k2, k3;

    // Accumulating state

    /**
     * Current block of buffered input
     */
    private final byte[] currentBlock = new byte[BLOCK_SIZE];

    /**
     * Current offset in input buffer
     */
    private int currentBlockOffset = 0;

    /**
     * Polynomial accumulator
     */
    private int h0, h1, h2, h3, h4;

    /**
     * Constructs a Poly1305 MAC, where the key passed to init() will be used directly.
     */
    Poly1305Impl()
    {
        this.cipher = null;
    }

    /**
     * Constructs a Poly1305 MAC, using a 128 bit block cipher.
     */
    Poly1305Impl(final BlockCipher cipher)
    {
        if (cipher.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException("Poly1305 requires a 128 bit block cipher.");
        }
        this.cipher = cipher;
    }

    /**
     * Initialises the Poly1305 MAC.
     *
     * @param params if used with a block cipher, then a {@link ParametersWithIV} containing a 128 bit
     *               nonce and a {@link KeyParameter} with a 256 bit key complying to the
     *               {@link Poly1305KeyGenerator Poly1305 key format}, otherwise just the
     *               {@link KeyParameter}.
     */
    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        byte[] nonce = null;

        if (cipher != null)
        {
            if (!(params instanceof ParametersWithIV))
            {
                throw new IllegalArgumentException("Poly1305 requires an IV when used with a block cipher");
            }

            ParametersWithIV ivParams = (ParametersWithIV)params;
            nonce = ivParams.getIV();
            params = ivParams.getParameters();
        }

        if (!(params instanceof KeyParameterImpl))
        {
            throw new IllegalArgumentException("Poly1305 requires a key.");
        }

        KeyParameter keyParams = (KeyParameterImpl)params;

        setKey(keyParams.getKey(), nonce);

        reset();
    }

    private void setKey(final byte[] key, final byte[] nonce)
    {
        if (key.length != 32)
        {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits");
        }
        if (cipher != null && (nonce == null || nonce.length != BLOCK_SIZE))
        {
            throw new IllegalArgumentException("Poly1305 requires a 128 bit IV");
        }

        // Extract r portion of key (and "clamp" the values)
        int t0 = Pack.littleEndianToInt(key, 0);
        int t1 = Pack.littleEndianToInt(key, 4);
        int t2 = Pack.littleEndianToInt(key, 8);
        int t3 = Pack.littleEndianToInt(key, 12);

        // NOTE: The masks perform the key "clamping" implicitly
        r0 = t0 & 0x03FFFFFF;
        r1 = ((t0 >>> 26) | (t1 << 6)) & 0x03FFFF03;
        r2 = ((t1 >>> 20) | (t2 << 12)) & 0x03FFC0FF;
        r3 = ((t2 >>> 14) | (t3 << 18)) & 0x03F03FFF;
        r4 = (t3 >>> 8) & 0x000FFFFF;

        // Precompute multipliers
        s1 = r1 * 5;
        s2 = r2 * 5;
        s3 = r3 * 5;
        s4 = r4 * 5;

        final byte[] kBytes;
        final int kOff;

        if (cipher == null)
        {
            kBytes = key;
            kOff = BLOCK_SIZE;
        }
        else
        {
            // Compute encrypted nonce
            kBytes = new byte[BLOCK_SIZE];
            kOff = 0;

            cipher.init(true, new KeyParameterImpl(key, BLOCK_SIZE, BLOCK_SIZE));
            cipher.processBlock(nonce, 0, kBytes, 0);
        }

        k0 = Pack.littleEndianToInt(kBytes, kOff + 0);
        k1 = Pack.littleEndianToInt(kBytes, kOff + 4);
        k2 = Pack.littleEndianToInt(kBytes, kOff + 8);
        k3 = Pack.littleEndianToInt(kBytes, kOff + 12);
    }

    public String getAlgorithmName()
    {
        return cipher == null ? "Poly1305" : "Poly1305-" + cipher.getAlgorithmName();
    }

    public int getMacSize()
    {
        return BLOCK_SIZE;
    }

    public void update(final byte in)
        throws IllegalStateException
    {
        singleByte[0] = in;
        update(singleByte, 0, 1);
    }

    public void update(final byte[] in, final int inOff, final int len)
        throws DataLengthException,
        IllegalStateException
    {
        int copied = 0;
        while (len > copied)
        {
            if (currentBlockOffset == BLOCK_SIZE)
            {
                processBlock();
                currentBlockOffset = 0;
            }

            int toCopy = Math.min((len - copied), BLOCK_SIZE - currentBlockOffset);
            System.arraycopy(in, copied + inOff, currentBlock, currentBlockOffset, toCopy);
            copied += toCopy;
            currentBlockOffset += toCopy;
        }

    }

    private void processBlock()
    {
        if (currentBlockOffset < BLOCK_SIZE)
        {
            currentBlock[currentBlockOffset] = 1;
            for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++)
            {
                currentBlock[i] = 0;
            }
        }

        final long t0 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 0);
        final long t1 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 4);
        final long t2 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 8);
        final long t3 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 12);

        h0 += t0 & 0x3ffffff;
        h1 += (((t1 << 32) | t0) >>> 26) & 0x3ffffff;
        h2 += (((t2 << 32) | t1) >>> 20) & 0x3ffffff;
        h3 += (((t3 << 32) | t2) >>> 14) & 0x3ffffff;
        h4 += (t3 >>> 8);

        if (currentBlockOffset == BLOCK_SIZE)
        {
            h4 += (1 << 24);
        }

        long tp0 = mul32x32_64(h0, r0) + mul32x32_64(h1, s4) + mul32x32_64(h2, s3) + mul32x32_64(h3, s2) + mul32x32_64(h4, s1);
        long tp1 = mul32x32_64(h0, r1) + mul32x32_64(h1, r0) + mul32x32_64(h2, s4) + mul32x32_64(h3, s3) + mul32x32_64(h4, s2);
        long tp2 = mul32x32_64(h0, r2) + mul32x32_64(h1, r1) + mul32x32_64(h2, r0) + mul32x32_64(h3, s4) + mul32x32_64(h4, s3);
        long tp3 = mul32x32_64(h0, r3) + mul32x32_64(h1, r2) + mul32x32_64(h2, r1) + mul32x32_64(h3, r0) + mul32x32_64(h4, s4);
        long tp4 = mul32x32_64(h0, r4) + mul32x32_64(h1, r3) + mul32x32_64(h2, r2) + mul32x32_64(h3, r1) + mul32x32_64(h4, r0);

        h0 = (int)tp0 & 0x3ffffff;
        tp1 += (tp0 >>> 26);
        h1 = (int)tp1 & 0x3ffffff;
        tp2 += (tp1 >>> 26);
        h2 = (int)tp2 & 0x3ffffff;
        tp3 += (tp2 >>> 26);
        h3 = (int)tp3 & 0x3ffffff;
        tp4 += (tp3 >>> 26);
        h4 = (int)tp4 & 0x3ffffff;
        h0 += (int)(tp4 >>> 26) * 5;
        h1 += (h0 >>> 26);
        h0 &= 0x3ffffff;
    }

    public int doFinal(final byte[] out, final int outOff)
        throws DataLengthException,
        IllegalStateException
    {
        if (outOff + BLOCK_SIZE > out.length)
        {
            throw new OutputLengthException("Output buffer is too short.");
        }

        if (currentBlockOffset > 0)
        {
            // Process padded final block
            processBlock();
        }

        h1 += (h0 >>> 26);
        h0 &= 0x3ffffff;
        h2 += (h1 >>> 26);
        h1 &= 0x3ffffff;
        h3 += (h2 >>> 26);
        h2 &= 0x3ffffff;
        h4 += (h3 >>> 26);
        h3 &= 0x3ffffff;
        h0 += (h4 >>> 26) * 5;
        h4 &= 0x3ffffff;
        h1 += (h0 >>> 26);
        h0 &= 0x3ffffff;

        int g0, g1, g2, g3, g4, b;
        g0 = h0 + 5;
        b = g0 >>> 26;
        g0 &= 0x3ffffff;
        g1 = h1 + b;
        b = g1 >>> 26;
        g1 &= 0x3ffffff;
        g2 = h2 + b;
        b = g2 >>> 26;
        g2 &= 0x3ffffff;
        g3 = h3 + b;
        b = g3 >>> 26;
        g3 &= 0x3ffffff;
        g4 = h4 + b - (1 << 26);

        b = (g4 >>> 31) - 1;
        int nb = ~b;
        h0 = (h0 & nb) | (g0 & b);
        h1 = (h1 & nb) | (g1 & b);
        h2 = (h2 & nb) | (g2 & b);
        h3 = (h3 & nb) | (g3 & b);
        h4 = (h4 & nb) | (g4 & b);

        long f0, f1, f2, f3;
        f0 = (((h0) | (h1 << 26)) & 0xffffffffl) + (0xffffffffL & k0);
        f1 = (((h1 >>> 6) | (h2 << 20)) & 0xffffffffl) + (0xffffffffL & k1);
        f2 = (((h2 >>> 12) | (h3 << 14)) & 0xffffffffl) + (0xffffffffL & k2);
        f3 = (((h3 >>> 18) | (h4 << 8)) & 0xffffffffl) + (0xffffffffL & k3);

        Pack.intToLittleEndian((int)f0, out, outOff);
        f1 += (f0 >>> 32);
        Pack.intToLittleEndian((int)f1, out, outOff + 4);
        f2 += (f1 >>> 32);
        Pack.intToLittleEndian((int)f2, out, outOff + 8);
        f3 += (f2 >>> 32);
        Pack.intToLittleEndian((int)f3, out, outOff + 12);

        reset();
        return BLOCK_SIZE;
    }

    public void reset()
    {
        currentBlockOffset = 0;

        h0 = h1 = h2 = h3 = h4 = 0;
    }

    private static final long mul32x32_64(int i1, int i2)
    {
        return (i1 & 0xFFFFFFFFL) * i2;
    }
}
