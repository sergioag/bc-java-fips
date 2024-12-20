package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPublicKey;
import org.bouncycastle.util.Arrays;

class ProvDSAPublicKey
    implements DSAPublicKey, ProvKey<AsymmetricDSAPublicKey>
{
    private static final long serialVersionUID = 1752452449903495175L;

    private transient AsymmetricDSAPublicKey baseKey;

    ProvDSAPublicKey(
        Algorithm algorithm,
        DSAPublicKey baseKey)
    {
        this.baseKey = new AsymmetricDSAPublicKey(algorithm, DSAUtils.extractParams(baseKey.getParams()), baseKey.getY());
    }

    ProvDSAPublicKey(
        Algorithm algorithm,
        DSAPublicKeySpec keySpec)
    {
        this.baseKey = new AsymmetricDSAPublicKey(algorithm, DSAUtils.extractParams(keySpec), keySpec.getY());
    }

    ProvDSAPublicKey(
        AsymmetricDSAPublicKey baseKey)
    {
        this.baseKey = baseKey;
    }

    public AsymmetricDSAPublicKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return "DSA";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public BigInteger getY()
    {
        return baseKey.getY();
    }

    public DSAParams getParams()
    {
        if (baseKey.getDomainParameters() == null)
        {
            return null;
        }
        return DSAUtils.convertParams(baseKey.getDomainParameters());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof DSAPublicKey))
        {
            return false;
        }

        if (o instanceof ProvDSAPublicKey)
        {
            ProvDSAPublicKey other = (ProvDSAPublicKey)o;

            return this.baseKey.equals(other.baseKey);
        }
        else
        {
            DSAPublicKey other = (DSAPublicKey)o;

            return Arrays.areEqual(this.getEncoded(), other.getEncoded());
        }
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

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricDSAPublicKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }

    public String toString()
    {
        return KeyUtil.publicKeyToString("DSA", baseKey.getY(), baseKey.getDomainParameters());
    }
}
