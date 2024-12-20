package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

public class HKDFParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] salt;
    private final byte[] info;

    /**
     * Construct parameters for HKDF, specifying both the optional salt and
     * optional info.
     *
     * @param salt the salt to use, may be null for a salt for hashLen zeros
     * @param info the info to use, may be null for an info field of zero bytes
     */
    public HKDFParameterSpec(final byte[] salt, final byte[] info)
    {
        this.salt = Arrays.clone(salt);
        this.info = Arrays.clone(info);
    }

    /**
     * Construct parameters for HKDF, specifying just optional salt.
     *
     * @param salt the salt to use, may be null for a salt for hashLen zeros
     */
    public HKDFParameterSpec(final byte[] salt)
    {
        this(salt, null);
    }
    
    /**
     * Returns the salt, or null if the salt should be generated as a byte array
     * of HashLen zeros.
     *
     * @return the salt, or null
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    /**
     * Returns the info field, which may be empty (null is converted to empty).
     *
     * @return the info field, never null
     */
    public byte[] getInfo()
    {
        return Arrays.clone(info);
    }
}
