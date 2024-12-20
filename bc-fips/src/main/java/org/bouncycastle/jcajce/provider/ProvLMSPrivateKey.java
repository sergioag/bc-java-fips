package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPublicKey;
import org.bouncycastle.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.jcajce.interfaces.LMSPublicKey;

class ProvLMSPrivateKey
    implements Destroyable, LMSPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient AsymmetricLMSPrivateKey baseKey;

    ProvLMSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.baseKey = new AsymmetricLMSPrivateKey(keyInfo);
    }

    ProvLMSPrivateKey(AsymmetricLMSPrivateKey baseKey)
    {
        this.baseKey = baseKey;
    }

    public long getIndex()
    {
        if (getUsagesRemaining() == 0)
        {
            throw new IllegalStateException("key exhausted");
        }

        return baseKey.getIndex();
    }

    public long getUsagesRemaining()
    {
        return baseKey.getUsagesRemaining();
    }

    public LMSPrivateKey extractKeyShard(int usageCount)
    {
        return new ProvLMSPrivateKey(baseKey.extractKeyShard(usageCount));
    }

    public String getAlgorithm()
    {
        return getBaseKey().getAlgorithm().getName();
    }

    public String getFormat()
    {
        KeyUtil.checkDestroyed(this);

        return "PKCS#8";
    }

    public byte[] getPublicData()
    {
        return getBaseKey().getPublicData();
    }

    public byte[] getEncoded()
    {
        return getBaseKey().getEncoded();
    }

    public void destroy()
    {
        baseKey.destroy();
    }

    public boolean isDestroyed()
    {
        return baseKey.isDestroyed();
    }

    AsymmetricLMSPrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(this);

        return baseKey;
    }

    public int getLevels()
    {
        KeyUtil.checkDestroyed(this);

        return baseKey.getL();
    }

    public LMSPublicKey getPublicKey()
    {
        return new ProvLMSPublicKey(new AsymmetricLMSPublicKey(baseKey.getL(), baseKey.getPublicData()));
    }

    public String toString()
    {
        if (isDestroyed())
        {
             return KeyUtil.destroyedPrivateKeyToString("LMS");
        }

        AsymmetricLMSPublicKey pubKey = new AsymmetricLMSPublicKey(baseKey.getL(), baseKey.getPublicData());

        return KeyUtil.keyToString("Private Key", getAlgorithm(), pubKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvLMSPrivateKey))
        {
            return false;
        }

        ProvLMSPrivateKey other = (ProvLMSPrivateKey)o;

        return baseKey.equals(other.baseKey);
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

        baseKey = new AsymmetricLMSPrivateKey(enc);
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

        out.writeObject(this.getEncoded());
    }
}
