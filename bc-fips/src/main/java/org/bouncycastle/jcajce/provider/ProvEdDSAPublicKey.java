package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;

class ProvEdDSAPublicKey
    implements EdDSAPublicKey
{
    static final long serialVersionUID = 1L;

    private transient AsymmetricEdDSAPublicKey baseKey;

    ProvEdDSAPublicKey(AsymmetricEdDSAPublicKey pubKey)
    {
        this.baseKey = pubKey;
    }

    /**
     * Construct a key from an encoding of a SubjectPublicKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    ProvEdDSAPublicKey(byte[] encoding)
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

        if (!(o instanceof ProvEdDSAPublicKey))
        {
            return false;
        }

        ProvEdDSAPublicKey other = (ProvEdDSAPublicKey)o;

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
}
