package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPublicKey;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.util.Arrays;

class Prov11XDHPrivateKey
    implements Destroyable, XDHPrivateKey, XECPrivateKey
{
    static final long serialVersionUID = 1L;

    private transient AsymmetricXDHPrivateKey baseKey;

    Prov11XDHPrivateKey(AsymmetricXDHPrivateKey privKey)
    {
        this.baseKey = privKey;
    }

    Prov11XDHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        baseKey = new AsymmetricXDHPrivateKey(keyInfo);
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
    
    public AsymmetricXDHPrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(this);

        return baseKey;
    }

    public XDHPublicKey getPublicKey()
    {
        return new Prov11XDHPublicKey(new AsymmetricXDHPublicKey(baseKey.getAlgorithm(), baseKey.getPublicData()));
    }

    public String toString()
    {
        if (isDestroyed())
        {
             return KeyUtil.destroyedPrivateKeyToString("XDH");
        }

        AsymmetricXDHPublicKey pubKey = new AsymmetricXDHPublicKey(baseKey.getAlgorithm(), baseKey.getPublicData());

        return KeyUtil.keyToString("Private Key", getAlgorithm(), pubKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof XECPrivateKey))
        {
            return false;
        }

        XECPrivateKey other = (XECPrivateKey)o;

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

        baseKey = new AsymmetricXDHPrivateKey(enc);
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

    @Override
    public Optional<byte[]> getScalar()
    {
        return Optional.of(baseKey.getSecret());
    }

    @Override
    public AlgorithmParameterSpec getParams()
    {
        if (baseKey.getAlgorithm().equals(EdEC.Algorithm.X448))
        {
            return NamedParameterSpec.X448;
        }
        else
        {
            return NamedParameterSpec.X25519;
        }
    }
}
