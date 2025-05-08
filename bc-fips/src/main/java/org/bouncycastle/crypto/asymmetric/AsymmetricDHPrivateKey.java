package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.ValidationParams;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.util.Arrays;

/**
 * Class for Diffie-Hellman private keys.
 */
public final class AsymmetricDHPrivateKey
    extends AsymmetricDHKey
    implements AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private int hashCode;
    private BigInteger x;

    public AsymmetricDHPrivateKey(Algorithm algorithm, DHDomainParameters params, BigInteger x)
    {
        super(algorithm, params);

        this.x = x;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricDHPrivateKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, PrivateKeyInfo.getInstance(enc));
    }

    public AsymmetricDHPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
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
     * Return the algorithm this Diffie-Hellman key is for.
     *
     * @return the key's algorithm.
     */
    public final Algorithm getAlgorithm()
    {
        KeyUtils.checkDestroyed(this);

        return super.getAlgorithm();
    }

    /**
     * Return the Diffie-Hellman domain parameters associated with this key.
     *
     * @return the Diffie-Hellman domain parameters for this key.
     */
    public final DHDomainParameters getDomainParameters()
    {
        DHDomainParameters parameters = super.getDomainParameters();

        KeyUtils.checkDestroyed(this);

        return parameters;
    }

    public final byte[] getEncoded()
    {
        DHDomainParameters params = this.getDomainParameters();

        if (params.getQ() == null)
        {
            if (getAlgorithm().getName().startsWith("ELGAMAL"))
            {
                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(params.getP(), params.getG())), new ASN1Integer(getX()));
            }

            return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(params.getP(), params.getG(), params.getL())), new ASN1Integer(getX()));
        }
        else
        {
            DHValidationParameters validationParameters = params.getValidationParameters();
            if (validationParameters != null)
            {
                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(params.getP(), params.getG(), params.getQ(), params.getJ(),
                    new ValidationParams(new DERBitString(validationParameters.getSeed()), new ASN1Integer(validationParameters.getCounter())))), new ASN1Integer(getX()));
            }
            else
            {
                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(params.getP(), params.getG(), params.getQ(), params.getJ(), null)), new ASN1Integer(getX()));
            }
        }
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

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricDHPrivateKey))
        {
            return false;
        }

        AsymmetricDHPrivateKey other = (AsymmetricDHPrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        if (this.isDestroyed() || other.isDestroyed())
        {
            return false;
        }

        return Arrays.constantTimeAreEqual(getX().toByteArray(), other.getX().toByteArray()) && this.getDomainParameters().equals(other.getDomainParameters());
    }
}
