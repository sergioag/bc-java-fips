package org.bouncycastle.crypto.general;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;

/**
 * GOST R 34.10-2001/2012 Signature Algorithm
 */
class EcGost3410Signer
    implements org.bouncycastle.crypto.internal.DSA
{
    EcKeyParameters key;

    SecureRandom random;

    public void init(
        boolean forSigning,
        CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.random = rParam.getRandom();
                this.key = (EcPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                throw new IllegalArgumentException("No random provided where one required.");
            }
        }
        else
        {
            this.key = (EcPublicKeyParameters)param;
        }
    }

    /**
     * generate a signature for the given message using the key we were
     * initialised with. For conventional GOST3410 the message should be a GOST3411
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public BigInteger[] generateSignature(
        byte[] message)
    {
        byte[] mRev = new byte[message.length]; // conversion is little-endian
        for (int i = 0; i != mRev.length; i++)
        {
            mRev[i] = message[mRev.length - 1 - i];
        }

        BigInteger e = new BigInteger(1, mRev);

        EcDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();
        BigInteger d = ((EcPrivateKeyParameters)key).getD();

        BigInteger r, s;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                do
                {
                    k = new BigInteger(n.bitLength(), random);
                }
                while (k.equals(ECConstants.ZERO));

                ECPoint p = basePointMultiplier.multiply(ec.getG(), k).normalize();

                r = p.getAffineXCoord().toBigInteger().mod(n);
            }
            while (r.equals(ECConstants.ZERO));

            s = (k.multiply(e)).add(d.multiply(r)).mod(n);
        }
        while (s.equals(ECConstants.ZERO));

        return new BigInteger[]{r, s};
    }

    /**
     * return true if the value r and s represent a GOST3410 signature for
     * the passed in message (for standard GOST3410 the message should be
     * a GOST3411 hash of the real message to be verified).
     */
    public boolean verifySignature(
        byte[] message,
        BigInteger r,
        BigInteger s)
    {
        byte[] mRev = new byte[message.length]; // conversion is little-endian
        for (int i = 0; i != mRev.length; i++)
        {
            mRev[i] = message[mRev.length - 1 - i];
        }

        BigInteger e = new BigInteger(1, mRev);
        BigInteger n = key.getParameters().getN();

        // r in the range [1,n-1]
        if (r.compareTo(ECConstants.ONE) < 0 || r.compareTo(n) >= 0)
        {
            return false;
        }

        // s in the range [1,n-1]
        if (s.compareTo(ECConstants.ONE) < 0 || s.compareTo(n) >= 0)
        {
            return false;
        }

        BigInteger v = BigIntegers.modOddInverseVar(n, e);

        BigInteger z1 = s.multiply(v).mod(n);
        BigInteger z2 = (n.subtract(r)).multiply(v).mod(n);

        ECPoint G = key.getParameters().getG(); // P
        ECPoint Q = ((EcPublicKeyParameters)key).getQ();

        ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, z1, Q, z2).normalize();

        // components must be bogus.
        if (point.isInfinity())
        {
            return false;
        }

        BigInteger R = point.getAffineXCoord().toBigInteger().mod(n);

        return R.equals(r);
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
