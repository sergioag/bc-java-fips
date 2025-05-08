package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

final class Ed25519PublicKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = Ed25519.PUBLIC_KEY_SIZE;

    private final byte[] data = new byte[KEY_SIZE];

    private final Ed25519 ed25519 = new Ed25519()
    {
        @Override
        protected Digest createDigest()
        {
            return FipsSHS.createDigest(FipsSHS.Algorithm.SHA512);
        }
    };

    public Ed25519PublicKeyParameters(byte[] buf)
    {
        this(validate(buf), 0);
    }

    public Ed25519PublicKeyParameters(byte[] buf, int off)
    {
        super(false);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }

    public Ed25519PublicKeyParameters(InputStream input)
        throws IOException
    {
        super(false);

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of Ed25519 public key");
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
            case Ed25519.Algorithm.Ed25519:
            {
                if (null != ctx)
                {
                    throw new IllegalArgumentException("ctx");
                }

                return ed25519.verify(sig, sigOff, data, 0, msg, msgOff, msgLen);
            }
            case Ed25519.Algorithm.Ed25519ctx:
            {
                return ed25519.verify(sig, sigOff, data, 0, ctx, msg, msgOff, msgLen);
            }
            case Ed25519.Algorithm.Ed25519ph:
            {
                if (Ed25519.PREHASH_SIZE != msgLen)
                {
                    throw new IllegalArgumentException("msgLen");
                }

                return ed25519.verifyPrehash(sig, sigOff, data, 0, ctx, msg, msgOff);
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
