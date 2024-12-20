package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.internal.DerivationParameters;
import org.bouncycastle.util.Arrays;

/**
 * Parameter class for the HKDFBytesGenerator class.
 */
public class HKDFParameters
    implements DerivationParameters
{
    private final KeyParameter hkdfKey;
    private final byte[] info;

    public HKDFParameters(KeyParameter hkdfKey, final byte[] info)
    {
        if (hkdfKey == null)
        {
            throw new IllegalArgumentException(
                "hkdfKey (input keying material) should not be null");
        }

        this.hkdfKey = hkdfKey;

        if (info == null)
        {
            this.info = new byte[0];
        }
        else
        {
            this.info = Arrays.clone(info);
        }
    }

    /**
     * Returns the input keying material or seed.
     *
     * @return the keying material
     */
    public KeyParameter getKey()
    {
        return hkdfKey;
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
