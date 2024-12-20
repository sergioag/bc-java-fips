package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.util.Arrays;

final class ProvSecretKeySpec
    extends SecretKeySpec
    implements Destroyable, ProvKey<SymmetricKey>
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private static final long serialVersionUID = -1861292622640337039L;

    private transient ValidatedSymmetricKey baseKey;

    public ProvSecretKeySpec(ValidatedSymmetricKey key)
    {
        this(key, Utils.getBaseName(key.getAlgorithm()));
    }

    public ProvSecretKeySpec(ValidatedSymmetricKey key, String standardName)
    {
        super(key.getKeyBytes(), standardName);

        this.baseKey = key;
    }

    public SymmetricKey getBaseKey()
    {
        KeyUtil.checkDestroyed(this);

        return new SymmetricSecretKey(baseKey.getAlgorithm(), baseKey.getKeyBytes());
    }

    public String getAlgorithm()
    {
        KeyUtil.checkDestroyed(this);

        return super.getAlgorithm();
    }

    public String getFormat()
    {
        KeyUtil.checkDestroyed(this);

        return "RAW";
    }

    public byte[] getEncoded()
    {
        KeyUtil.checkDestroyed(this);

        return Arrays.clone(baseKey.getKeyBytes());
    }

    public void destroy()
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            baseKey = null;
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new ValidatedSymmetricKey(alg, enc);
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
