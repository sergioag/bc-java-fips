package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Class for Elliptic Curve (EC) private keys.
 */
public final class AsymmetricECPrivateKey
    extends AsymmetricECKey
    implements AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[]     publicKey;

    private int        hashCode;
    private BigInteger d;

    public AsymmetricECPrivateKey(Algorithm ecAlg, ECDomainParametersID domainParametersID, BigInteger s)
    {
        this(ecAlg, domainParametersID, s, null);
    }

    public AsymmetricECPrivateKey(Algorithm ecAlg, ECDomainParameters domainParameters, BigInteger s)
    {
        this(ecAlg, domainParameters, s, null);
    }

    public AsymmetricECPrivateKey(Algorithm ecAlg, ECDomainParameters domainParameters, BigInteger s, ECPoint w)
    {
        super(ecAlg, domainParameters);

        this.d = s;
        this.publicKey = extractPublicKeyBytes(w);
        this.hashCode = calculateHashCode();
    }

    public AsymmetricECPrivateKey(Algorithm ecAlg, ECDomainParametersID domainParametersID, BigInteger s, ECPoint w)
    {
        super(ecAlg, domainParametersID);

        this.d = s;
        this.publicKey = extractPublicKeyBytes(w);
        this.hashCode = calculateHashCode();
    }

    public AsymmetricECPrivateKey(Algorithm ecAlg, byte[] encoding)
    {
        this(ecAlg, PrivateKeyInfo.getInstance(encoding));
    }

    public AsymmetricECPrivateKey(Algorithm ecAlg, PrivateKeyInfo privateKeyInfo)
    {
        this(ecAlg, privateKeyInfo.getPrivateKeyAlgorithm(), parsePrivateKey(privateKeyInfo));
    }

    private AsymmetricECPrivateKey(Algorithm ecAlg, AlgorithmIdentifier algorithmIdentifier, ECPrivateKey privateKey)
    {
        super(ecAlg, algorithmIdentifier);

        this.d = privateKey.getKey();
        DERBitString wEnc = privateKey.getPublicKey();
        // really this should be getOctets() but there are keys with padbits out in the wild
        this.publicKey = (wEnc == null) ? null : wEnc.getBytes();
        this.hashCode = calculateHashCode();
    }

    private static ECPrivateKey parsePrivateKey(PrivateKeyInfo privateKeyInfo)
    {
        try
        {
            return ECPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse EC private key: " + e.getMessage(), e);
        }
    }

    private byte[] extractPublicKeyBytes(ECPoint w)
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkDestroyed(this);

        if (w == null)
        {
            return null;
        }

        return w.getEncoded(false);
    }

    public final byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        KeyUtils.checkDestroyed(this);

        X962Parameters params = KeyUtils.buildCurveParameters(this.getDomainParameters());
        int            orderBitLength = KeyUtils.getOrderBitLength(this.getDomainParameters());

        org.bouncycastle.asn1.sec.ECPrivateKey keyStructure;

        if (publicKey != null)
        {
            keyStructure = new ECPrivateKey(orderBitLength, this.getS(), new DERBitString(publicKey), params);
        }
        else
        {
            keyStructure = new ECPrivateKey(orderBitLength, this.getS(), params);
        }

        return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);
    }

    /**
      * Return the algorithm this Elliptic Curve key is for.
      *
      * @return the key's algorithm.
      */
    public final Algorithm getAlgorithm()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkDestroyed(this);

        return super.getAlgorithm();
    }

    /**
     * Return the Elliptic Curve domain parameters associated with this key.
     *
     * @return the EC domain parameters for the key.
     */
    public final ECDomainParameters getDomainParameters()
    {
        checkApprovedOnlyModeStatus();

        ECDomainParameters dp = super.getDomainParameters();

        KeyUtils.checkDestroyed(this);

        return dp;
    }

    public BigInteger getS()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        BigInteger dVal = d;

        KeyUtils.checkDestroyed(this);

        return dVal;
    }

    public void destroy()
    {
        checkApprovedOnlyModeStatus();

        if (!hasBeenDestroyed.getAndSet(true))
        {
            this.d = null;
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

        if (!(o instanceof AsymmetricECPrivateKey))
        {
            return false;
        }

        AsymmetricECPrivateKey other = (AsymmetricECPrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        if (!getS().equals(other.getS()))
        {
            return false;
        }

        // we ignore the public point encoding.

        return this.getDomainParameters().equals(other.getDomainParameters());
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = d.hashCode();
        result = 31 * result + this.getDomainParameters().hashCode();
        return result;
    }
}
