package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.DerivationFunction;
import org.bouncycastle.crypto.internal.DerivationParameters;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.internal.params.KDFParameters;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Arrays;

class NoCounterKDFGenerator
    implements DerivationFunction
{
    private final Digest digest;

    private final Mac mac;

    private byte[] shared;

    private byte[] otherInfo;

    private int hLen;

    private int requiredLen;


    public NoCounterKDFGenerator(Digest digest)
    {
        this.digest = digest;
        this.mac = null;
        this.hLen = digest.getDigestSize();
    }


    public NoCounterKDFGenerator(Mac mac)
    {
        this.mac = mac;
        this.digest = null;
        this.hLen = mac.getMacSize();
    }

    @Override
    public void init(DerivationParameters param)
    {
        if (param instanceof KDFParameters)
        {
            KDFParameters p = (KDFParameters)param;

            shared = p.getSharedSecret();

            otherInfo = p.getIV();
            if (mac != null)
            {

                byte[] salt = p.getSalt();

                if (p.getSalt() == null)
                {
                    if (mac instanceof HMac)
                    {
                        salt = new byte[((HMac)mac).getUnderlyingDigest().getByteLength()];
                    }
                    else if (mac instanceof KMAC)
                    {
                        salt = new byte[(((KMAC)mac).getByteLength()) - 4];
                    }
                    else
                    {
                        throw new IllegalArgumentException("cannot recognise MAC");
                    }
                }

                mac.init(new KeyParameterImpl(salt));
            }
        }
        else
        {
            throw new IllegalArgumentException("KDF parameters required for KDF generator");
        }
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {
        if (digest != null)
        {
            return digestGenerateBytes(out, outOff, len);
        }
        else
        {
            return macGenerateBytes(out, outOff, len);
        }
    }

    private int macGenerateBytes(byte[] out, int outOff, int len)
    {
        mac.update(shared, 0, shared.length);

        if (otherInfo != null)
        {
            mac.update(otherInfo, 0, otherInfo.length);
        }

        if (mac instanceof KMAC)
        {
            ((KMAC)mac).doFinal(out, outOff, len);
        }
        else
        {
            if (len > hLen)
            {
                throw new IllegalArgumentException("requested length too large for KDF output");
            }

            byte[] hashBuf = new byte[hLen];

            mac.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, out, outOff, len);

            Arrays.fill(hashBuf, (byte)0);
        }

        return len;
    }

    private int digestGenerateBytes(byte[] out, int outOff, int len)
    {
        if (len > hLen)
        {
            throw new IllegalArgumentException("requested length too large for KDF output");
        }

        digest.update(shared, 0, shared.length);

        if (otherInfo != null)
        {
            digest.update(otherInfo, 0, otherInfo.length);
        }

        byte[] hashBuf = new byte[hLen];

        digest.doFinal(hashBuf, 0);

        System.arraycopy(hashBuf, 0, out, outOff, len);

        Arrays.fill(hashBuf, (byte)0);

        return len;
    }
}

