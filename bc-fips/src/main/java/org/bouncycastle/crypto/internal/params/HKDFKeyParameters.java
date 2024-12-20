package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.util.Arrays;

/**
 * Parameter class for the HKDFKeyGenerator class.
 */
public class HKDFKeyParameters
{
    private final byte[] ikm;
    private final boolean skipExpand;
    private final byte[] salt;

    public HKDFKeyParameters(final byte[] ikm, final boolean skip,
                             final byte[] salt)
    {
        if (ikm == null)
        {
            throw new IllegalArgumentException(
                "IKM (input keying material) should not be null");
        }

        this.ikm = Arrays.clone(ikm);

        this.skipExpand = skip;

        if (salt == null || salt.length == 0)
        {
            this.salt = null;
        }
        else
        {
            this.salt = Arrays.clone(salt);
        }
    }

    /**
     * Returns the input keying material or seed.
     *
     * @return the keying material
     */
    public byte[] getIKM()
    {
        return Arrays.clone(ikm);
    }

    /**
     * Returns if step 1: extract has to be skipped or not
     *
     * @return true for skipping, false for no skipping of step 1
     */
    public boolean skipExtract()
    {
        return skipExpand;
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
}
