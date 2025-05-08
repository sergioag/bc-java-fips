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

        return super.getEncoded();
    }

    public char[] getPassword()
    {
        KeyUtil.checkDestroyed(this);

        return password;
    }

    public byte[] getSalt()
    {
        KeyUtil.checkDestroyed(this);

        return Arrays.clone(salt);
    }

    public int getIterationCount()
    {
        KeyUtil.checkDestroyed(this);

        return iterationCount;
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
