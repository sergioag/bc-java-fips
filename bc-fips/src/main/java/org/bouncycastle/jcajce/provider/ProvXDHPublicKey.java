package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPublicKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.util.Arrays;

class ProvXDHPublicKey
    implements XDHPublicKey
{
    static final long serialVersionUID = 1L;

    private transient AsymmetricXDHPublicKey baseKey;

    ProvXDHPublicKey(AsymmetricXDHPublicKey pubKey)
    {
        this.baseKey = pubKey;
    }

    /**
     * Construct a key from an encoding of a SubjectPublicKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    ProvXDHPublicKey(byte[] encoding)
    {
        this.baseKey = new AsymmetricXDHPublicKey(encoding);
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

    public AsymmetricXDHPublicKey getBaseKey()
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

        if (!(o instanceof ProvXDHPublicKey))
        {
            return false;
        }

        ProvXDHPublicKey other = (ProvXDHPublicKey)o;

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

        this.baseKey = new AsymmetricXDHPublicKey(enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
