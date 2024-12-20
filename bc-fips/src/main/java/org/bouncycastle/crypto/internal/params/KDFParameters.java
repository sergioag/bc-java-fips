package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.internal.DerivationParameters;

/**
 * parameters for Key derivation functions for IEEE P1363a
 */
public class KDFParameters
    implements DerivationParameters
{
    byte[]  iv;
    byte[]  shared;
    byte[]  salt;

    public KDFParameters(
        byte[]  shared,
        byte[]  iv)
    {
        this.shared = shared;
        this.iv = iv;
    }

    public KDFParameters(
        byte[] shared,
        byte[] salt,
        byte[] iv)
    {
        this.shared = shared;
        this.salt = salt;
        this.iv = iv;
    }

    public byte[] getSharedSecret()
    {
        return shared;
    }

    public byte[] getIV()
    {
        return iv;
    }

    public byte[] getSalt()
    {
        return salt;
    }
}
