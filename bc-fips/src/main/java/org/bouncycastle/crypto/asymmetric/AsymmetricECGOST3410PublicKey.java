package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Class for keys for GOST R 34.10-2001 (ECGOST) public keys.
 */
public final class AsymmetricECGOST3410PublicKey
    extends AsymmetricGOST3410Key<ECDomainParameters>
    implements AsymmetricPublicKey
{
    private ECPoint w;

    public AsymmetricECGOST3410PublicKey(Algorithm algorithm, GOST3410Parameters<ECDomainParameters> params, ECPoint w)
    {
        super(algorithm, params);

        this.w = KeyUtils.validated(getParameters().getDomainParameters().getCurve(), w);
    }

    public AsymmetricECGOST3410PublicKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, SubjectPublicKeyInfo.getInstance(enc));
    }

    public AsymmetricECGOST3410PublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
    {
        super(algorithm, ecAcceptable, publicKeyInfo.getAlgorithm());

        this.w = KeyUtils.validated(getParameters().getDomainParameters().getCurve(), parsePublicKey(publicKeyInfo));
    }

    private ECPoint parsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
    {
        ASN1OctetString key;

        try
        {
            key = ASN1OctetString.getInstance(publicKeyInfo.parsePublicKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error recovering public key: " + e.getMessage(), e);
        }

        byte[] x;
        byte[] y;
        byte[] keyEnc = key.getOctets();
        if (keyEnc.length == 64)
        {
            x = new byte[32];
            y = new byte[32];

            for (int i = 0; i != x.length; i++)
            {
                x[i] = keyEnc[32 - 1 - i];
            }

            for (int i = 0; i != y.length; i++)
            {
                y[i] = keyEnc[64 - 1 - i];
            }
        }
        else
        {
            x = new byte[64];
            y = new byte[64];

            for (int i = 0; i != x.length; i++)
            {
                x[i] = keyEnc[64 - 1 - i];
            }

            for (int i = 0; i != y.length; i++)
            {
                y[i] = keyEnc[128 - 1 - i];
            }
        }
 
        return this.getParameters().getDomainParameters().getCurve().validatePoint(new BigInteger(1, x), new BigInteger(1, y));
    }

    public ECPoint getW()
    {
        return w;
    }

    public byte[] getEncoded()
    {
        BigInteger bX = this.w.getAffineXCoord().toBigInteger();
        BigInteger bY = this.w.getAffineYCoord().toBigInteger();
        byte[] encKey;

        if (bX.bitLength() > 264 || bY.bitLength() > 264)
        {
            encKey = new byte[128];

            extractBytes(encKey, 0, bX);
            extractBytes(encKey, 64, bY);
        }
        else
        {
            encKey = new byte[64];

            extractBytes(encKey, 0, bX);
            extractBytes(encKey, 32, bY);
        }

        if (getParameters().getPublicKeyParamSet() != null)
        {
            GOST3410PublicKeyAlgParameters pubParams = new GOST3410PublicKeyAlgParameters(getParameters().getPublicKeyParamSet(), getParameters().getDigestParamSet(), getParameters().getEncryptionParamSet());

            if (encKey.length == 128)
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, pubParams), new DEROctetString(encKey));
            }
            if (pubParams.getEncryptionParamSet().on(RosstandartObjectIdentifiers.id_tc26))
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, pubParams), new DEROctetString(encKey));
            }
            else
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, pubParams), new DEROctetString(encKey));
            }
        }
        else
        {
            if (encKey.length == 128)
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512), new DEROctetString(encKey));
            }
            if (getParameters().getDomainParameters() instanceof NamedECDomainParameters)
            {
                ASN1ObjectIdentifier id = ((NamedECDomainParameters)getParameters().getDomainParameters()).getID();
                if (id.on(RosstandartObjectIdentifiers.id_tc26))
                {
                    return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256), new DEROctetString(encKey));
                }
            }
            return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001), new DEROctetString(encKey));
        }
    }

    private void extractBytes(byte[] encKey, int offSet, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        int half = encKey.length / 2;
        if (val.length < half)
        {
            byte[] tmp = new byte[half];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != half; i++)
        {
            encKey[offSet + i] = val[val.length - 1 - i];
        }
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricECGOST3410PublicKey))
        {
            return false;
        }

        AsymmetricECGOST3410PublicKey other = (AsymmetricECGOST3410PublicKey)o;

        return w.equals(other.w) && this.getParameters().equals(other.getParameters());
    }

    @Override
    public int hashCode()
    {
        int result = w.hashCode();
        result = 31 * result + this.getParameters().hashCode();
        return result;
    }
}
