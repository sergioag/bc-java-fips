package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPrivateKey;

class ProvDHPrivateKey
    implements Destroyable, DHPrivateKey
{
    static final long serialVersionUID = 311058815616901812L;

    private transient AsymmetricDHPrivateKey baseKey;

    ProvDHPrivateKey(
        Algorithm algorithm,
        DHPrivateKey key)
    {
        this.baseKey = new AsymmetricDHPrivateKey(algorithm, DHUtils.extractParams(key.getParams()), key.getX());
    }

    ProvDHPrivateKey(
        Algorithm algorithm,
        DHPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricDHPrivateKey(algorithm, DHUtils.extractParams(keySpec), keySpec.getX());
    }

    ProvDHPrivateKey(
        AsymmetricDHPrivateKey key)
    {
        this.baseKey = key;
    }


    public String getAlgorithm()
    {
        KeyUtil.checkDestroyed(this);

        return "DH";
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

    public DHParameterSpec getParams()
    {
        return DHUtils.convertParams(baseKey.getDomainParameters());
    }

    public BigInteger getX()
    {
        return baseKey.getX();
    }

    AsymmetricDHPrivateKey getBaseKey()
    {
        return baseKey;
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
            return KeyUtil.destroyedPrivateKeyToString("DH");
        }

        try
        {
            return KeyUtil.privateKeyToString("DH", baseKey.getX(), baseKey.getDomainParameters());
        }
        catch (Exception e)
        {
            return KeyUtil.restrictedToString("DH");
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvDHPrivateKey))
        {
            return false;
        }

        ProvDHPrivateKey other = (ProvDHPrivateKey)o;

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

        baseKey = new AsymmetricDHPrivateKey(alg, enc);
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
