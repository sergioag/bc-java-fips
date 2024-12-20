package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPublicKey;
import org.bouncycastle.jcajce.interfaces.LMSPublicKey;

class ProvLMSPublicKey
    implements LMSPublicKey
{
    private static final long serialVersionUID = 1L;
    
    private transient AsymmetricLMSPublicKey baseKey;

    ProvLMSPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.baseKey = new AsymmetricLMSPublicKey(keyInfo);
    }

    ProvLMSPublicKey(AsymmetricLMSPublicKey baseKey)
    {
        this.baseKey = baseKey;
    }

    /**
     * @return name of the algorithm - "LMS"
     */
    public final String getAlgorithm()
    {
        return "LMS";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public String getFormat()
    {
        return "X.509";
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof ProvLMSPublicKey)
        {
            ProvLMSPublicKey otherKey = (ProvLMSPublicKey)o;

            return baseKey.equals(otherKey.baseKey);
        }

        return false;
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }
    
    public int getLevels()
    {
        return baseKey.getL();
    }

    AsymmetricLMSPublicKey getBaseKey()
    {
        return baseKey;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricLMSPublicKey(enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
