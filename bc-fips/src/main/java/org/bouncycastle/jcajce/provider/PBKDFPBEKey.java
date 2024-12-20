package org.bouncycastle.jcajce.provider;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.bouncycastle.util.Arrays;

// we need this for legacy reasons
class PBKDFPBEKey
    extends SecretKeySpec
    implements Destroyable, PBEKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
    
    private final char[] password;
    private final byte[] salt;
    private final int iterationCount;

    public PBKDFPBEKey(byte[] bytes, String keyAlg, PBEKeySpec pbeSpec)
    {
        super(bytes, keyAlg);
        this.password = pbeSpec.getPassword();
        this.salt = pbeSpec.getSalt();
        this.iterationCount = pbeSpec.getIterationCount();
    }

    public String getAlgorithm()
    {
        String rv = super.getAlgorithm();

        KeyUtil.checkDestroyed(this);

        return rv;
    }

    public String getFormat()
    {
        KeyUtil.checkDestroyed(this);

        return "RAW";
    }

    public byte[] getEncoded()
    {
        byte[] encoded = super.getEncoded();

        KeyUtil.checkDestroyed(this);

        return encoded;
    }

    public char[] getPassword()
    {
        char[] rv = Arrays.clone(password);

        KeyUtil.checkDestroyed(this);

        return rv;
    }

    public byte[] getSalt()
    {
        byte[] clone = Arrays.clone(salt);

        KeyUtil.checkDestroyed(this);

        return clone;
    }

    public int getIterationCount()
    {
        int rv = this.iterationCount;

        KeyUtil.checkDestroyed(this);

        return rv;
    }

    public void destroy()
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            if (password != null)
            {
                Arrays.fill(password, (char)0);
            }
            if (salt != null)
            {
                Arrays.fill(salt, (byte)0);
            }
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }
}
