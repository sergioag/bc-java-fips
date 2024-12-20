package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Xof;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

class CSHAKEDigest
    extends SHAKEDigest
{
    private static final byte[] ZERO_BYTE = new byte[1];
    private static final byte[] padding = new byte[100];

    private final byte[] diff;

    CSHAKEDigest(CSHAKEDigest source)
    {
        super(source);

        this.diff = Arrays.clone(source.diff);
    }

    CSHAKEDigest(int bitLength, byte[] N, byte[] S)
    {
        super(bitLength);

        // we self-test with no parameters, this verifies the underlying SHAKE function is working correctly.
        if (bitLength == 128)
        {
            SelfTestExecutor.validate(FipsSHS.Algorithm.cSHAKE128, this, new KatTest<Xof>(Hex.decode("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")));
        }
        else
        {
            SelfTestExecutor.validate(FipsSHS.Algorithm.cSHAKE256, this, new KatTest<Xof>(Hex.decode("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4")));
        }

        if ((N == null || N.length == 0) && (S == null || S.length == 0))
        {
            diff = null;
        }
        else
        {
            diff = Arrays.concatenate(XofUtils.leftEncode(rate / 8), encodeString(N), encodeString(S));
            diffPadAndAbsorb();
        }
    }

    private void diffPadAndAbsorb()
    {
        int blockSize = rate / 8;
        absorb(diff, 0, diff.length * 8);

        int delta = diff.length % blockSize;

        if (delta != 0)
        {
            int required = blockSize - delta;

            while (required > padding.length)
            {
                absorb(padding, 0, padding.length * 8);
                required -= padding.length;
            }

            absorb(padding, 0, required * 8);
        }
    }

    private byte[] encodeString(byte[] str)
    {
        if (str == null || str.length == 0)
        {
            return XofUtils.leftEncode(0);
        }

        return Arrays.concatenate(XofUtils.leftEncode(str.length * 8L), str);
    }

    public String getAlgorithmName()
        {
            return "CSHAKE" + fixedOutputLength;
        }

    public int doOutput(byte[] out, int outOff, int outLen)
    {
        if (diff != null)
        {
            if (!squeezing)
            {
                absorb(ZERO_BYTE, 0, 2);
            }

            squeeze(out, outOff, ((long)outLen) * 8);

            return outLen;
        }
        else
        {
            return super.doOutput(out, outOff, outLen);
        }
    }

    public void reset()
    {
        super.reset();
        
        if (diff != null)
        {
            diffPadAndAbsorb();
        }
    }

    private static class KatTest<T extends Digest>
        implements BasicKatTest<T>
    {
        private static final byte[] stdShaVector = Strings.toByteArray("abc");
        private final byte[] kat;

        KatTest(byte[] kat)
        {
            this.kat = kat;
        }

        public boolean hasTestPassed(Digest digest)
        {
            digest.update(stdShaVector, 0, stdShaVector.length);

            byte[] result = new byte[digest.getDigestSize()];

            digest.doFinal(result, 0);

            digest.reset();

            return Arrays.areEqual(result, kat);
        }
    }
}
