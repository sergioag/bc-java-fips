package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.util.BigIntegers;

/**
 * Class for RSA private keys.
 */
public final class AsymmetricRSAPrivateKey
    extends AsymmetricRSAKey
    implements Destroyable, AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger p;
    private BigInteger q;
    private BigInteger dp;
    private BigInteger dq;
    private BigInteger qInv;

    private int hashCode;

    public AsymmetricRSAPrivateKey(Algorithm algorithm, BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger qInv)
    {
        super(algorithm, modulus);

        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qInv = qInv;
        this.hashCode = calculateHashCode();

        BigInteger pSub1 = p.subtract(BigIntegers.ONE);
        BigInteger qSub1 = q.subtract(BigIntegers.ONE);

        boolean valid = p.multiply(q).equals(modulus);

        valid &= dp.compareTo(BigIntegers.ONE) > 0 & dp.compareTo(pSub1) < 0
            & dp.multiply(publicExponent).mod(pSub1).equals(BigIntegers.ONE);
        valid &= dq.compareTo(BigIntegers.ONE) > 0 & dq.compareTo(qSub1) < 0
            & dq.multiply(publicExponent).mod(qSub1).equals(BigIntegers.ONE);
        valid &= qInv.compareTo(BigIntegers.ONE) > 0 & qInv.compareTo(p) < 0
            & qInv.multiply(q).mod(p).equals(BigIntegers.ONE);

        if (!valid)
        {
            throw new IllegalArgumentException("private values mismatch");
        }
    }

    public AsymmetricRSAPrivateKey(Algorithm algorithm, BigInteger modulus, BigInteger privateExponent)
    {
        super(algorithm, modulus);

        this.privateExponent = privateExponent;
        this.publicExponent = BigInteger.ZERO;
        this.p = BigInteger.ZERO;
        this.q = BigInteger.ZERO;
        this.dp = BigInteger.ZERO;
        this.dq = BigInteger.ZERO;
        this.qInv = BigInteger.ZERO;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricRSAPrivateKey(Algorithm algorithm, byte[] privateKeyInfoEncoding)
    {
        this(algorithm, getPrivateKeyInfo(privateKeyInfoEncoding));
    }

    public AsymmetricRSAPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
    {
        this(algorithm, privateKeyInfo.getPrivateKeyAlgorithm(), parsePrivateKey(privateKeyInfo));
    }

    private static PrivateKeyInfo getPrivateKeyInfo(byte[] encoding)
    {
        try
        {
            return PrivateKeyInfo.getInstance(encoding);
        }
        catch (IllegalArgumentException e)
        {
            // OpenSSL's old format, and some others - Try just the private key data.
            try
            {
                return new PrivateKeyInfo(DEF_ALG_ID, ASN1Sequence.getInstance(encoding));
            }
            catch (IOException e1)
            {
                throw new IllegalArgumentException("Unable to parse private key: " + e.getMessage(), e);
            }
        }
    }

    private static RSAPrivateKey parsePrivateKey(PrivateKeyInfo privateKeyInfo)
    {
        try
        {
            return RSAPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse private key: " + e.getMessage(), e);
        }
    }

    private AsymmetricRSAPrivateKey(Algorithm algorithm, AlgorithmIdentifier algId, RSAPrivateKey privKey)
    {
        // we're importing from an encoding, let's just make sure the modulus is actually valid.
        super(algorithm, algId, KeyUtils.validatedModulus(privKey.getModulus()));

        this.publicExponent = privKey.getPublicExponent();
        this.privateExponent = privKey.getPrivateExponent();
        this.p = privKey.getPrime1();
        this.q = privKey.getPrime2();
        this.dp = privKey.getExponent1();
        this.dq = privKey.getExponent2();
        this.qInv = privKey.getCoefficient();
        this.hashCode = calculateHashCode();
    }

    /**
     * Return the algorithm this RSA key is for.
     *
     * @return the key's algorithm.
     */
    public Algorithm getAlgorithm()
    {
        KeyUtils.checkDestroyed(this);

        return super.getAlgorithm();
    }

    /**
     * Return the modulus for this RSA key.
     *
     * @return the key's modulus.
     */
    public BigInteger getModulus()
    {
        BigInteger rv = super.getModulus();

        KeyUtils.checkDestroyed(this);

        return rv;
    }

    public BigInteger getPublicExponent()
    {
        BigInteger rv = publicExponent;

        KeyUtils.checkDestroyed(this);

        return rv;
    }

    public BigInteger getPrivateExponent()
    {
        return fieldValue(privateExponent);
    }

    public BigInteger getP()
    {
        return fieldValue(p);
    }

    public BigInteger getQ()
    {
        return fieldValue(q);
    }

    public BigInteger getDP()
    {
        return fieldValue(dp);
    }

    public BigInteger getDQ()
    {
        return fieldValue(dq);
    }

    public BigInteger getQInv()
    {
        return fieldValue(qInv);
    }

    public final byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkDestroyed(this);

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        return KeyUtils.getEncodedPrivateKeyInfo(rsaAlgIdentifier, new RSAPrivateKey(getModulus(), publicExponent, getPrivateExponent(), getP(), getQ(), getDP(), getDQ(), getQInv()));
    }

    public void destroy()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        if (!hasBeenDestroyed.getAndSet(true))
        {
            this.privateExponent = this.publicExponent = null;
            this.p = this.q = this.dp = this.dq = this.qInv = null;
            this.hashCode = -1;

            super.zeroize();
        }
    }

    public boolean isDestroyed()
    {
        checkApprovedOnlyModeStatus();

        return hasBeenDestroyed.get();
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }
        if (!(o instanceof AsymmetricRSAPrivateKey))
        {
            return false;
        }

        AsymmetricRSAPrivateKey other = (AsymmetricRSAPrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        return KeyUtils.isFieldEqual(modulus, other.modulus)
            && KeyUtils.isFieldEqual(privateExponent, other.privateExponent)
            && KeyUtils.isFieldEqual(publicExponent, other.publicExponent)
            && KeyUtils.isFieldEqual(p, other.p)
            && KeyUtils.isFieldEqual(q, other.q)
            && KeyUtils.isFieldEqual(dp, other.dp)
            && KeyUtils.isFieldEqual(dq, other.dq)
            && KeyUtils.isFieldEqual(qInv, other.qInv);
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = getModulus().hashCode();
        result = 31 * result + publicExponent.hashCode();
        result = 31 * result + privateExponent.hashCode();
        result = 31 * result + p.hashCode();
        result = 31 * result + q.hashCode();
        result = 31 * result + dp.hashCode();
        result = 31 * result + dq.hashCode();
        result = 31 * result + qInv.hashCode();
        return result;
    }

    /*
    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        destroy();
    }
    */

    private void checkCanRead()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        KeyUtils.checkDestroyed(this);
    }

    private BigInteger fieldValue(BigInteger value)
    {
        checkCanRead();

        return value;
    }
}
