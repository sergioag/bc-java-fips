package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;

class Prov15EdDSAPrivateKey
    implements Destroyable, EdDSAPrivateKey, EdECPrivateKey
{
    static final long serialVersionUID = 1L;

    private transient AsymmetricEdDSAPrivateKey baseKey;
    private transient AsymmetricEdDSAPublicKey basePublicKey;

    Prov15EdDSAPrivateKey(AsymmetricEdDSAPrivateKey privKey, AsymmetricEdDSAPublicKey pubKey)
    {
        this.baseKey = privKey;
        this.basePublicKey = pubKey;
    }

    Prov15EdDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        baseKey = new AsymmetricEdDSAPrivateKey(keyInfo);
        basePublicKey = new AsymmetricEdDSAPublicKey(baseKey.getAlgorithm(), baseKey.getPublicData());
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

    AsymmetricEdDSAPrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(this);

        return baseKey;
    }

    public EdDSAPublicKey getPublicKey()
    {
        return new Prov15EdDSAPublicKey(basePublicKey);
    }

    public String toString()
    {
        if (isDestroyed())
        {
             return KeyUtil.destroyedPrivateKeyToString("EdDSA");
        }

        return KeyUtil.keyToString("Private Key", getAlgorithm(), basePublicKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof Prov15EdDSAPrivateKey)
        {
            return this.baseKey.equals(((Prov15EdDSAPrivateKey)o).baseKey);
        }

        return false;
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

        baseKey = new AsymmetricEdDSAPrivateKey(enc);
        basePublicKey = new AsymmetricEdDSAPublicKey(baseKey.getAlgorithm(), baseKey.getPublicData());
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
    public Optional<byte[]> getBytes()
    {
        return Optional.of(baseKey.getSecret());
    }

    @Override
    public NamedParameterSpec getParams()
    {
        NamedParameterSpec z = null;
        if (baseKey.getAlgorithm().getName().startsWith("Ed448"))
        {
            return NamedParameterSpec.ED448;
        }
        else
        {
            return NamedParameterSpec.ED25519;
        }
    }
}
