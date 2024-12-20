package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;

class ProvECPrivateKey
    implements Destroyable, ECPrivateKey, ProvKey<AsymmetricECPrivateKey>
{
    static final long serialVersionUID = 994553197664784084L;

    private transient AsymmetricECPrivateKey baseKey;

    ProvECPrivateKey(
        Algorithm algorithm,
        ECPrivateKey key)
    {
        ECDomainParameters domainParameters = ECUtil.convertFromSpec(key.getParams());

        this.baseKey = new AsymmetricECPrivateKey(algorithm, domainParameters, key.getS());
    }

    ProvECPrivateKey(
        Algorithm algorithm,
        ECPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricECPrivateKey(algorithm, ECUtil.convertFromSpec(keySpec.getParams()), keySpec.getS());
    }

    ProvECPrivateKey(
        AsymmetricECPrivateKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricECPrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(this);
        
        return baseKey;
    }

    public String getAlgorithm()
    {
        KeyUtil.checkDestroyed(this);

        return "EC";
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        KeyUtil.checkDestroyed(this);

        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public ECParameterSpec getParams()
    {
        return ECUtil.convertToSpec(baseKey.getDomainParameters());
    }

    public BigInteger getS()
    {
        return baseKey.getS();
    }

    public void destroy()
    {
        baseKey.destroy();
    }

    public boolean isDestroyed()
    {
        return baseKey.isDestroyed();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvECPrivateKey))
        {
            return false;
        }

        ProvECPrivateKey other = (ProvECPrivateKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    public String toString()
    {
        if (isDestroyed())
        {
            return KeyUtil.destroyedPrivateKeyToString("EC");
        }

        try
        {
            return KeyUtil.privateKeyToString("EC", baseKey.getS(), baseKey.getDomainParameters());
        }
        catch (Exception e)
        {
            return KeyUtil.restrictedToString("EC");
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricECPrivateKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        if (isDestroyed())
        {
            throw new IOException("key has been destroyed");
        }
        
        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }
}
