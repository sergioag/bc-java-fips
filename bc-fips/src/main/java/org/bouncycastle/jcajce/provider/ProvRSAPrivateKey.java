package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.util.Strings;

class ProvRSAPrivateKey
    implements Destroyable, RSAPrivateKey, ProvKey<AsymmetricRSAPrivateKey>
{
    static final long serialVersionUID = 5110188922551353628L;

    private transient AsymmetricRSAPrivateKey baseKey;

    ProvRSAPrivateKey(
        Algorithm algorithm,
        RSAPrivateKey key)
     {
         this.baseKey = new AsymmetricRSAPrivateKey(algorithm, key.getModulus(), key.getPrivateExponent());
     }

    ProvRSAPrivateKey(
        Algorithm algorithm,
        RSAPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricRSAPrivateKey(algorithm, keySpec.getModulus(), keySpec.getPrivateExponent());
    }

    ProvRSAPrivateKey(
        AsymmetricRSAPrivateKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricRSAPrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(baseKey);

        return baseKey;
    }

    public BigInteger getModulus()
    {
        return baseKey.getModulus();
    }

    public BigInteger getPrivateExponent()
    {
        return baseKey.getPrivateExponent();
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the encoding format we produce in getEncoded().
     */
    public String getFormat()
    {
        KeyUtil.checkDestroyed(baseKey);

        return "PKCS#8";
    }

    public String getAlgorithm()
    {
        KeyUtil.checkDestroyed(baseKey);

        if ("RSA/PSS".equals(baseKey.getAlgorithm().getName()))
        {
            return "RSASSA-PSS";
        }

        return "RSA";
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
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        if (isDestroyed())
        {
            buf.append("RSA Private Key [DESTROYED]").append(nl);
        }
        else
        {
            buf.append("RSA Private Key [").append(KeyUtil.generateFingerPrint(this.getModulus())).append("],[]").append(nl);
            buf.append("         modulus: ").append(this.getModulus().toString(16)).append(nl);
        }

        return buf.toString();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvRSAPrivateKey))
        {
            return false;
        }

        ProvRSAPrivateKey other = (ProvRSAPrivateKey)o;

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

        baseKey = new AsymmetricRSAPrivateKey(alg, enc);
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
