package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.util.Strings;

/**
 * A provider representation for a RSA private key, with CRT factors included.
 */
class ProvRSAPrivateCrtKey
    implements Destroyable, RSAPrivateKey, RSAPrivateCrtKey, ProvKey<AsymmetricRSAPrivateKey>
{
    static final long serialVersionUID = 7834723820638524718L;

    private transient AsymmetricRSAPrivateKey baseKey;

    ProvRSAPrivateCrtKey(
        Algorithm algorithm,
        RSAPrivateCrtKey key)
     {
         this.baseKey = new AsymmetricRSAPrivateKey(algorithm, key.getModulus(), key.getPublicExponent(), key.getPrivateExponent(),
                                          key.getPrimeP(), key.getPrimeQ(), key.getPrimeExponentP(), key.getPrimeExponentQ(), key.getCrtCoefficient());
     }

    ProvRSAPrivateCrtKey(
        Algorithm algorithm,
        RSAPrivateCrtKeySpec keySpec)
    {
        this.baseKey = new AsymmetricRSAPrivateKey(algorithm, keySpec.getModulus(), keySpec.getPublicExponent(), keySpec.getPrivateExponent(),
                                         keySpec.getPrimeP(), keySpec.getPrimeQ(), keySpec.getPrimeExponentP(), keySpec.getPrimeExponentQ(), keySpec.getCrtCoefficient());
    }

    ProvRSAPrivateCrtKey(
        AsymmetricRSAPrivateKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricRSAPrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(baseKey);

        return baseKey;
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

    public BigInteger getPrivateExponent()
    {
        return baseKey.getPrivateExponent();
    }

    public BigInteger getModulus()
    {
        return baseKey.getModulus();
    }

    /**
     * return the public exponent.
     *
     * @return the public exponent.
     */
    public BigInteger getPublicExponent()
    {
        return baseKey.getPublicExponent();
    }

    /**
     * return the prime P.
     *
     * @return the prime P.
     */
    public BigInteger getPrimeP()
    {
        return baseKey.getP();
    }

    /**
     * return the prime Q.
     *
     * @return the prime Q.
     */
    public BigInteger getPrimeQ()
    {
        return baseKey.getQ();
    }

    /**
     * return the prime exponent for P.
     *
     * @return the prime exponent for P.
     */
    public BigInteger getPrimeExponentP()
    {
        return baseKey.getDP();
    }

    /**
     * return the prime exponent for Q.
     *
     * @return the prime exponent for Q.
     */
    public BigInteger getPrimeExponentQ()
    {
        return baseKey.getDQ();
    }

    /**
     * return the CRT coefficient.
     *
     * @return the CRT coefficient.
     */
    public BigInteger getCrtCoefficient()
    {
        return baseKey.getQInv();
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

        if (!(o instanceof ProvRSAPrivateCrtKey))
        {
            return false;
        }

        ProvRSAPrivateCrtKey other = (ProvRSAPrivateCrtKey)o;

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

    public String toString()
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        if (isDestroyed())
        {
            buf.append("RSA Private CRT Key [DESTROYED]").append(nl);
        }
        else
        {
            buf.append("RSA Private CRT Key [").append(
                KeyUtil.generateFingerPrint(this.getModulus())).append("]")
                .append(",[").append(
                KeyUtil.generateExponentFingerprint(this.getPublicExponent())).append("]").append(nl);

            buf.append("             modulus: ").append(this.getModulus().toString(16)).append(nl);
            buf.append("     public exponent: ").append(this.getPublicExponent().toString(16)).append(nl);
        }

        return buf.toString();
    }
}
