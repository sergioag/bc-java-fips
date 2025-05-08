package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.Xof;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

final class Ed448PublicKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = Ed448.PUBLIC_KEY_SIZE;

    private final byte[] data = new byte[KEY_SIZE];

    private final Ed448 ed448 = new Ed448()
    {
        @Override
        protected Xof createXof()
        {
            return (Xof) FipsSHS.createDigest(FipsSHS.Algorithm.SHAKE256);
        }
    };

    public Ed448PublicKeyParameters(byte[] buf)
    {
        this(validate(buf), 0);
    }

    public Ed448PublicKeyParameters(byte[] buf, int off)
    {
        super(false);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }

    public Ed448PublicKeyParameters(InputStream input)
        throws IOException
    {
        super(false);

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of Ed448 public key");
        }
    }

    public void encode(byte[] buf, int off)
    {
        System.arraycopy(data, 0, buf, off, KEY_SIZE);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(data);
    }

    public boolean verify(int algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
    {
        switch (algorithm)
        {
            case Ed448.Algorithm.Ed448:
            {
                return ed448.verify(sig, sigOff, data, 0, ctx, msg, msgOff, msgLen);
            }
            case Ed448.Algorithm.Ed448ph:
            {
                if (Ed448.PREHASH_SIZE != msgLen)
                {
                    throw new IllegalArgumentException("msgLen");
                }

                return ed448.verifyPrehash(sig, sigOff, data, 0, ctx, msg, msgOff);
            }
            default:
            {
                throw new IllegalArgumentException("algorithm");
            }
        }
    }

    private static byte[] validate(byte[] buf)
    {
        if (buf.length != KEY_SIZE)
        {
            throw new IllegalArgumentException("'buf' must have length " + KEY_SIZE);
        }
        return buf;
    }
}
