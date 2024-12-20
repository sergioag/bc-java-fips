package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class EcDomainParameters
    implements ECConstants
{
    private final ECCurve     curve;
    private final byte[]      seed;
    private final ECPoint     G;
    private final BigInteger  n;
    private final BigInteger  h;
    private final BigInteger  hInv;

    public EcDomainParameters(ECDomainParameters params)
    {
        this(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed(), null);
    }

    public EcDomainParameters(ECDomainParameters params, BigInteger hInv)
    {
        this(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed(), hInv);
    }

    private EcDomainParameters(
        ECCurve curve,
        ECPoint G,
        BigInteger n,
        BigInteger h,
        byte[] seed,
        BigInteger hInv)
    {
        if (curve == null)
        {
            throw new NullPointerException("curve");
        }
        if (n == null)
        {
            throw new NullPointerException("n");
        }
        // we can't check for h == null here as h is optional in X9.62 as it is not required for ECDSA

        this.curve = curve;
        this.G = validate(curve, G);
        this.n = n;
        this.h = h;
        this.seed = seed;
        this.hInv = hInv;
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    public ECPoint getG()
    {
        return G;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public BigInteger getHInv()
    {
        return hInv;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public boolean equals(
        Object  obj)
    {
        if (this == obj)
        {
            return true;
        }

        if ((obj instanceof EcDomainParameters))
        {
            EcDomainParameters pm = (EcDomainParameters)obj;

            return this.curve.equals(pm.curve) && this.G.equals(pm.G) && this.n.equals(pm.n) && this.h.equals(pm.h);
        }

        return false;
    }

    public int hashCode()
    {
        int hc = curve.hashCode();

        hc += 37 * G.hashCode();
        hc += 37 * n.hashCode();
        hc += 37 * h.hashCode();

        return hc;
    }

    static ECPoint validate(ECCurve c, ECPoint q)
    {
        if (q == null)
        {
            throw new IllegalArgumentException("Point has null value");
        }

        q = ECAlgorithms.importPoint(c, q).normalize();

        if (q.isInfinity())
        {
            throw new IllegalArgumentException("Point at infinity");
        }

        if (!q.isValid())
        {
            throw new IllegalArgumentException("Point not on curve");
        }

        return q;
    }
}
