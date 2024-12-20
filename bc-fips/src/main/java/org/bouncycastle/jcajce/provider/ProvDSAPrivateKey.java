package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPrivateKey;

class ProvDSAPrivateKey
    implements Destroyable, DSAPrivateKey, ProvKey<AsymmetricDSAPrivateKey>
{
    private static final long serialVersionUID = -4677259546958385734L;

    private transient AsymmetricDSAPrivateKey baseKey;

    ProvDSAPrivateKey(
        Algorithm algorithm,
        DSAPrivateKey key)
     {
         this.baseKey = new AsymmetricDSAPrivateKey(algorithm, DSAUtils.extractParams(key.getParams()), key.getX());
     }

    ProvDSAPrivateKey(
        Algorithm algorithm,
        DSAPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricDSAPrivateKey(algorithm, DSAUtils.extractParams(keySpec), keySpec.getX());
    }

    ProvDSAPrivateKey(
        AsymmetricDSAPrivateKey key)
    {
        this.baseKey = key;
    }

    public BigInteger getX()
    {
        return baseKey.getX();
    }

    public DSAParams getParams()
    {
        return DSAUtils.convertParams(baseKey.getDomainParameters());
    }

    public AsymmetricDSAPrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(this);
        
        return baseKey;
    }

    public String getAlgorithm()
    {
        KeyUtil.checkDestroyed(this);

        return "DSA";
    }

    public String getFormat()
    {
        KeyUtil.checkDestroyed(this);
        
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public void destroy()
    {
        baseKey.destroy();
    }

    public boolean isDestroyed()
    {
        return baseKey.isDestroyed();
    }

    public String toString()
    {
        if (isDestroyed())
        {
            return KeyUtil.destroyedPrivateKeyToString("DSA");
        }

        try
        {
            return KeyUtil.privateKeyToString("DSA", baseKey.getX(), baseKey.getDomainParameters());
        }
        catch (Exception e)
        {
            return KeyUtil.restrictedToString("DSA");
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvDSAPrivateKey))
        {
            return false;
        }

        ProvDSAPrivateKey other = (ProvDSAPrivateKey)o;

        return this.baseKey.equals(other.baseKey);
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

        baseKey = new AsymmetricDSAPrivateKey(alg, enc);
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
