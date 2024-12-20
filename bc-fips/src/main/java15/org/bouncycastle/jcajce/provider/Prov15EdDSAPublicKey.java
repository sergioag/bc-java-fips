package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;

class Prov15EdDSAPublicKey
    implements EdECPublicKey, EdDSAPublicKey
{
    static final long serialVersionUID = 1L;

    private transient AsymmetricEdDSAPublicKey baseKey;

    Prov15EdDSAPublicKey(AsymmetricEdDSAPublicKey pubKey)
    {
        this.baseKey = pubKey;
    }

    /**
     * Construct a key from an encoding of a SubjectPublicKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    Prov15EdDSAPublicKey(byte[] encoding)
    {
        this.baseKey = new AsymmetricEdDSAPublicKey(encoding);
    }


    public String getAlgorithm()
    {
        return baseKey.getAlgorithm().getName();
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getPublicData()
    {
        return baseKey.getPublicData();
    }
    
    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public AsymmetricEdDSAPublicKey getBaseKey()
    {
        return baseKey;
    }

    public String toString()
    {
        return KeyUtil.keyToString("Public Key", getAlgorithm(), baseKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof EdECPublicKey))
        {
            return false;
        }

        EdECPublicKey other = (EdECPublicKey)o;

        return Arrays.areEqual(other.getEncoded(), this.getEncoded());
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        this.baseKey = new AsymmetricEdDSAPublicKey(enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
    
    @Override
    public EdECPoint getPoint()
    {
        byte[] keyData = baseKey.getPublicData();

        Arrays.reverseInPlace(keyData);

        boolean xOdd = (keyData[0] & 0x80) != 0;
        keyData[0] &= 0x7f;

        return new EdECPoint(xOdd, new BigInteger(1, keyData));
    }

    @Override
    public NamedParameterSpec getParams()
    {
        if (baseKey.getAlgorithm().equals(EdEC.Algorithm.Ed448))
        {
            return NamedParameterSpec.ED448;
        }
        else
        {
            return NamedParameterSpec.ED25519;
        }
    }
}
