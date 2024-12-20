package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;

/**
 * Class for Digital Signature Algorithm (DSA) private keys.
 */
public final class AsymmetricDSAPrivateKey
    extends AsymmetricDSAKey
    implements AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private int hashCode;
    private BigInteger x;

    public AsymmetricDSAPrivateKey(Algorithm algorithm, DSADomainParameters params, BigInteger x)
    {
        super(algorithm, params);

        this.x = x;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricDSAPrivateKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, PrivateKeyInfo.getInstance(enc));
    }

    public AsymmetricDSAPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
    {
        super(algorithm, privateKeyInfo.getPrivateKeyAlgorithm());

        this.x = parsePrivateKey(privateKeyInfo);
        this.hashCode = calculateHashCode();
    }

    private static BigInteger parsePrivateKey(PrivateKeyInfo info)
    {
        try
        {
            return ASN1Integer.getInstance(info.parsePrivateKey()).getValue();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse DSA private key: " + e.getMessage(), e);
        }
    }

    /**
     * Return the algorithm this DSA key is for.
     *
     * @return the key's algorithm.
     */
    public final Algorithm getAlgorithm()
    {
        KeyUtils.checkDestroyed(this);

        return super.getAlgorithm();
    }

    /**
     * Return the DSA domain parameters associated with this key.
     *
     * @return the DSA domain parameters for this key.
     */
    public final DSADomainParameters getDomainParameters()
    {
        KeyUtils.checkDestroyed(this);

        return super.getDomainParameters();
    }

    public final byte[] getEncoded()
    {
        DSADomainParameters dsaDomainParameters = this.getDomainParameters();

        return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(dsaDomainParameters.getP(), dsaDomainParameters.getQ(), dsaDomainParameters.getG())), new ASN1Integer(getX()));
    }

    public BigInteger getX()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        BigInteger xVal = x;

        KeyUtils.checkDestroyed(this);

        return xVal;
    }

    public void destroy()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        if (!hasBeenDestroyed.getAndSet(true))
        {
            this.x = null;
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
    public int hashCode()
    {
        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = x.hashCode();
        result = 31 * result + this.getDomainParameters().hashCode();
        return result;
    }

    /*
    @Override
    protected void finalize()
        throws Throwable
    {
        //destroy();

        super.finalize();
    }
     */

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricDSAPrivateKey))
        {
            return false;
        }

        AsymmetricDSAPrivateKey other = (AsymmetricDSAPrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        return this.hashCode == other.hashCode
            && KeyUtils.isFieldEqual(this.x, other.x)
            && KeyUtils.isFieldEqual(this.domainParameters, other.domainParameters);
    }
}
