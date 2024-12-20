package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;

/**
 * Class for keys for GOST R 34.10-2001 (ECGOST) private keys.
 */
public final class AsymmetricECGOST3410PrivateKey
    extends AsymmetricGOST3410Key<ECDomainParameters>
    implements AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private int hashCode;

    private BigInteger x;

    public AsymmetricECGOST3410PrivateKey(Algorithm algorithm, GOST3410Parameters<ECDomainParameters> params, BigInteger x)
    {
        super(algorithm, params);

        this.x = x;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricECGOST3410PrivateKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, PrivateKeyInfo.getInstance(enc));
    }

    public AsymmetricECGOST3410PrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
    {
        super(algorithm, ecAcceptable, privateKeyInfo.getPrivateKeyAlgorithm());

        this.x = parsePrivateKey(privateKeyInfo);
        this.hashCode = calculateHashCode();
    }

    private static BigInteger parsePrivateKey(PrivateKeyInfo info)
    {
        try
        {
            ASN1Encodable keyData = info.parsePrivateKey();

            if (keyData instanceof ASN1Integer)
            {
                return ASN1Integer.getInstance(keyData).getPositiveValue();
            }
            else
            {
                byte[] encVal = ASN1OctetString.getInstance(keyData).getOctets();
                byte[] dVal = new byte[encVal.length];

                for (int i = 0; i != encVal.length; i++)
                {
                    dVal[i] = encVal[encVal.length - 1 - i];
                }

                return new BigInteger(1, dVal);
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse ECGOST3410 private key: " + e.getMessage(), e);
        }
    }

    public final byte[] getEncoded()
    {
        GOST3410Parameters<ECDomainParameters> parameters = getParameters();

        byte[] encKey;
        byte[] encS = this.getS().toByteArray();

        if (encS.length > 33)
        {
            encKey = new byte[64];
        }
        else
        {
            encKey = new byte[32];
        }
        extractBytes(encKey, this.getS());

        if (parameters.getPublicKeyParamSet() != null)
        {
            GOST3410PublicKeyAlgParameters pubParams = new GOST3410PublicKeyAlgParameters(parameters.getPublicKeyParamSet(), parameters.getDigestParamSet(), parameters.getEncryptionParamSet());

            if (encKey.length == 64)
            {
                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, pubParams), new DEROctetString(encKey));
            }
            if (pubParams.getEncryptionParamSet() != null && pubParams.getEncryptionParamSet().on(RosstandartObjectIdentifiers.id_tc26))
            {
                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, pubParams), new DEROctetString(encKey));
            }
            else
            {
                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, pubParams), new DEROctetString(encKey));
            }
        }
        else
        {
            if (encKey.length == 64)
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512), new DEROctetString(encKey));
            }
            if (parameters.getDomainParameters() instanceof NamedECDomainParameters)
            {
                ASN1ObjectIdentifier id = ((NamedECDomainParameters)getParameters().getDomainParameters()).getID();
                if (id.on(RosstandartObjectIdentifiers.id_tc26))
                {
                    return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256), new DEROctetString(encKey));
                }
            }
            return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001), new DEROctetString(encKey));
        }
    }

    private void extractBytes(byte[] encKey, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        if (val.length < encKey.length)
        {
            byte[] tmp = new byte[encKey.length];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != encKey.length; i++)
        {
            encKey[i] = val[val.length - 1 - i];
        }
    }

    /**
     * Return the algorithm this GOST R 34.10 key is for.
     *
     * @return the key's algorithm.
     */
    public final Algorithm getAlgorithm()
    {
        KeyUtils.checkDestroyed(this);

        return super.getAlgorithm();
    }

    /**
     * Return the domain parameters associated with this key.These will either
     * be for GOST R 34.10-1994 or GOST R 34.10-2001 depending on the key type.
     *
     * @return the GOST3410 domain parameters.
     */
    public final GOST3410Parameters<ECDomainParameters> getParameters()
    {
        KeyUtils.checkDestroyed(this);

        return super.getParameters();
    }

    public final BigInteger getS()
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
        result = 31 * result + this.getParameters().hashCode();
        return result;
    }

    /*
    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        //destroy();
    }
     */

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricECGOST3410PrivateKey))
        {
            return false;
        }

        AsymmetricECGOST3410PrivateKey other = (AsymmetricECGOST3410PrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        return KeyUtils.isFieldEqual(this.x, other.x) && KeyUtils.isFieldEqual(this.domainParameters, other.domainParameters);
    }
}
